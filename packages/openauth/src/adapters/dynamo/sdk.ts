/**
 * `fromDynamoDBClient` — wires the `DynamoExecutor` interface to a real AWS
 * SDK `DynamoDBDocumentClient`. Adapter consumers using AWS in production
 * call this factory once, then pass the returned executor into every store
 * adapter.
 *
 * The AWS SDK is imported via `@aws-sdk/lib-dynamodb` exclusively; the bare
 * client is the caller's concern (they can configure region, creds, retries,
 * etc.). This file is the **only** place in the package that imports the
 * AWS SDK at runtime — keeping the adapter surface clean and the bundle
 * lean for non-AWS consumers.
 *
 * @example
 *   import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
 *   import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb"
 *   const docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}))
 *   const exec = fromDynamoDBClient(docClient, "openauth")
 *   const tokenStore = new DynamoTokenStore({ exec, keyStore })
 */
import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb"
import {
  DeleteCommand,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb"

import type {
  DynamoDeleteInput,
  DynamoExecutor,
  DynamoGetInput,
  DynamoPutInput,
  DynamoQueryByGsiInput,
  DynamoQueryInput,
  DynamoUpdateConsumeRefreshInput,
} from "./client"

export function fromDynamoDBClient(
  client: DynamoDBDocumentClient,
  tableName: string,
): DynamoExecutor {
  return {
    async get(input: DynamoGetInput) {
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: input.key,
          ConsistentRead: input.consistentRead,
        }),
      )
      return (result.Item as Record<string, unknown> | undefined) ?? undefined
    },
    async put(input: DynamoPutInput) {
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: input.item,
          ...(input.condition === "not-exists"
            ? {
                ConditionExpression:
                  "attribute_not_exists(pk) AND attribute_not_exists(sk)",
              }
            : {}),
        }),
      )
    },
    async delete(input: DynamoDeleteInput) {
      const result = await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: input.key,
          ReturnValues: "ALL_OLD",
        }),
      )
      return (result.Attributes as Record<string, unknown> | undefined) ?? undefined
    },
    async consumeRefresh(input: DynamoUpdateConsumeRefreshInput) {
      try {
        const result = await client.send(
          new UpdateCommand({
            TableName: tableName,
            Key: input.key,
            UpdateExpression: "SET consumed_at = :now",
            ConditionExpression:
              "attribute_exists(pk) AND attribute_not_exists(consumed_at) AND expires_at > :now",
            ExpressionAttributeValues: { ":now": input.now },
            ReturnValues: "ALL_NEW",
          }),
        )
        return (result.Attributes as Record<string, unknown> | undefined) ?? null
      } catch (e) {
        if (isConditionalCheckFailed(e)) return null
        throw e
      }
    },
    async query(input: DynamoQueryInput) {
      const exprAttrValues: Record<string, unknown> = { ":pk": input.pk }
      let keyExpr = "pk = :pk"
      if (input.skBeginsWith) {
        keyExpr += " AND begins_with(sk, :skp)"
        exprAttrValues[":skp"] = input.skBeginsWith
      }
      let filterExpr: string | undefined
      if (input.filter) {
        const k = ":fv"
        filterExpr = `#attr = ${k}`
        exprAttrValues[k] = input.filter.equals
      }
      const result = await client.send(
        new QueryCommand({
          TableName: tableName,
          KeyConditionExpression: keyExpr,
          ConsistentRead: input.consistentRead,
          ExpressionAttributeValues: exprAttrValues,
          ...(filterExpr
            ? {
                FilterExpression: filterExpr,
                ExpressionAttributeNames: { "#attr": input.filter!.attribute },
              }
            : {}),
        }),
      )
      return (result.Items as Record<string, unknown>[] | undefined) ?? []
    },
    async queryByGsi(input: DynamoQueryByGsiInput) {
      const result = await client.send(
        new QueryCommand({
          TableName: tableName,
          IndexName: input.indexName,
          KeyConditionExpression: "#hk = :v",
          ExpressionAttributeNames: {
            "#hk": input.indexName === "family-index" ? "family" : "subject_key",
          },
          ExpressionAttributeValues: { ":v": input.hashKey },
        }),
      )
      return (result.Items as Record<string, unknown>[] | undefined) ?? []
    },
  }
}

function isConditionalCheckFailed(e: unknown): boolean {
  if (typeof e !== "object" || e === null) return false
  const name = (e as { name?: string }).name
  return name === "ConditionalCheckFailedException"
}
