/**
 * `DynamoExecutor` — the operation surface the adapters depend on.
 *
 * Keeps the AWS SDK out of the adapter's import graph. Production users
 * wire the executor via `fromDynamoDBClient(docClient, tableName)`; tests
 * supply an in-memory implementation (`test/helpers/dynamo-shim.ts`).
 *
 * All operations target a single table (the adapter is single-table by
 * design — pk + sk + optional GSIs). The executor knows the table name; the
 * adapter only passes keys + data.
 */

export type DynamoKey = { pk: string; sk: string }

/**
 * Strong read by primary key. `consistentRead` MUST be honoured for every
 * security-critical read (`getCode`, `getRefresh`, `getFlow`) — DynamoDB
 * defaults to eventually consistent reads which violate the contracts in
 * `ports/CONSISTENCY.md`.
 */
export type DynamoGetInput = {
  key: DynamoKey
  consistentRead: boolean
}

/**
 * Insert (`condition: "not-exists"`) or unconditional put. The adapter uses
 * not-exists for code / refresh / flow inserts so a duplicate token never
 * silently overwrites.
 */
export type DynamoPutInput = {
  item: Record<string, unknown> & DynamoKey
  condition?: "not-exists"
}

/**
 * Atomic delete-on-read — equivalent to `DeleteItem` with
 * `ReturnValues=ALL_OLD`. Concurrent calls resolve to exactly one winner
 * that gets the row back; losers get `undefined`.
 */
export type DynamoDeleteInput = {
  key: DynamoKey
}

/**
 * Conditional UPDATE used for the refresh-token rotation. Sets `consumed_at`
 * iff it is currently absent. Returns the post-update item on success;
 * resolves with `null` if the condition failed (`ConditionalCheckFailed`).
 */
export type DynamoUpdateConsumeRefreshInput = {
  key: DynamoKey
  now: number
}

/**
 * Query items by partition key (and optionally a sort-key prefix). Strongly
 * consistent for the refresh-revoke paths.
 */
export type DynamoQueryInput = {
  pk: string
  /** Sort-key prefix filter — emits `begins_with(sk, prefix)`. */
  skBeginsWith?: string
  consistentRead: boolean
  /** Filter by an attribute (e.g. `family = :v` for `revokeFamily` via GSI). */
  filter?: {
    attribute: string
    equals: string
  }
}

export type DynamoQueryByGsiInput = {
  /** GSI name configured on the table. */
  indexName: "family-index" | "subject-index"
  /** Hash key value on the GSI. */
  hashKey: string
}

export type DynamoExecutor = {
  get(input: DynamoGetInput): Promise<Record<string, unknown> | undefined>
  put(input: DynamoPutInput): Promise<void>
  /** Returns the deleted item if one was deleted; `undefined` otherwise. */
  delete(input: DynamoDeleteInput): Promise<Record<string, unknown> | undefined>
  /**
   * Atomic refresh-token claim. Returns the post-update item on success;
   * `null` if the condition failed (already-consumed race).
   */
  consumeRefresh(
    input: DynamoUpdateConsumeRefreshInput,
  ): Promise<Record<string, unknown> | null>
  query(input: DynamoQueryInput): Promise<Record<string, unknown>[]>
  queryByGsi(input: DynamoQueryByGsiInput): Promise<Record<string, unknown>[]>
}
