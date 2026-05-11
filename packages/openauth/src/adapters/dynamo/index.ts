/**
 * AWS DynamoDB adapter set.
 *
 * Single-table design with `pk` / `sk` primary key plus two GSIs for
 * refresh-token revocation:
 *
 *   `family-index`     hash = `family`        (revokeFamily)
 *   `subject-index`    hash = `subject_key`   (revokeBySubject) — value is `<tenantId>#<subjectId>`
 *
 * The adapter satisfies every contract in `ports/CONSISTENCY.md` provided
 * the underlying calls use `ConsistentRead=true` on the strong reads and
 * `ConditionExpression` on the rotation `UpdateItem` — both are handled by
 * `fromDynamoDBClient`.
 *
 * Wiring:
 * @example
 *   import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
 *   import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb"
 *   import {
 *     fromDynamoDBClient,
 *     DynamoTokenStore,
 *     DynamoSessionStore,
 *     // ...
 *   } from "@_mustachio/openauth/adapters/dynamo"
 *
 *   const docClient = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-1" }))
 *   const exec = fromDynamoDBClient(docClient, "openauth")
 *   const keyStore = new DynamoKeyStore({ exec })
 *   const tokenStore = new DynamoTokenStore({ exec, keyStore })
 *
 * Table creation is left to the operator (Terraform / CDK / `aws dynamodb
 * create-table`). The schema you need:
 *
 *   Table: openauth (or any name you choose)
 *     Hash key:  pk (S)
 *     Range key: sk (S)
 *     TTL attribute: `ttl` (epoch seconds)
 *
 *   GSI: family-index
 *     Hash key: family (S)
 *     Projection: ALL
 *
 *   GSI: subject-index
 *     Hash key: subject_key (S)
 *     Projection: ALL
 */
export { DynamoAuditLog, type DynamoAuditLogOptions } from "./audit-log"
export { DynamoConfigStore, type DynamoConfigStoreOptions } from "./config-store"
export { DynamoKeyStore, type DynamoKeyStoreOptions } from "./key-store"
export { DynamoMethodStore, type DynamoMethodStoreOptions } from "./method-store"
export {
  DynamoSessionStore,
  type DynamoSessionStoreOptions,
} from "./session-store"
export { DynamoTokenStore, type DynamoTokenStoreOptions } from "./token-store"
export { fromDynamoDBClient } from "./sdk"
export type {
  DynamoDeleteInput,
  DynamoExecutor,
  DynamoGetInput,
  DynamoKey,
  DynamoPutInput,
  DynamoQueryByGsiInput,
  DynamoQueryInput,
  DynamoUpdateConsumeRefreshInput,
} from "./client"
