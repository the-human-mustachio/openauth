/**
 * Postgres adapter set.
 *
 * Suitable for Node + Postgres deployments. Satisfies every contract in
 * `ports/CONSISTENCY.md` — `consumeCode` / `consumeFlow` use
 * `DELETE … RETURNING` for atomic single-winner CAS, `consumeRefresh` uses
 * `UPDATE … WHERE consumed_at IS NULL RETURNING payload`, and `KeyStore`
 * persists JWK material in JSONB columns.
 *
 * @example
 *   import postgres from "postgres"
 *   import {
 *     fromPostgresJs,
 *     migrate,
 *     PostgresTokenStore,
 *     PostgresSessionStore,
 *     PostgresKeyStore,
 *     PostgresConfigStore,
 *     PostgresMethodStore,
 *     PostgresAuditLog,
 *   } from "@_mustachio/openauth/adapters/postgres"
 *
 *   const sql = postgres(process.env.DATABASE_URL!)
 *   const exec = fromPostgresJs(sql)
 *   await migrate(exec)
 *   const keyStore = new PostgresKeyStore({ exec })
 *   const tokenStore = new PostgresTokenStore({ exec, keyStore })
 *   // ...
 */
export {
  fromPGlite,
  fromPostgresJs,
  type PGliteLike,
  type PostgresExecutor,
  type PostgresJsLike,
  type Row,
} from "./executor"
export { INITIAL_SCHEMA_SQL, migrate } from "./migrations"
export { PostgresAuditLog, type PostgresAuditLogOptions } from "./audit-log"
export {
  PostgresConfigStore,
  type PostgresConfigStoreOptions,
} from "./config-store"
export { PostgresKeyStore, type PostgresKeyStoreOptions } from "./key-store"
export {
  PostgresMethodStore,
  type PostgresMethodStoreOptions,
} from "./method-store"
export {
  PostgresSessionStore,
  type PostgresSessionStoreOptions,
} from "./session-store"
export {
  PostgresTokenStore,
  type PostgresTokenStoreOptions,
} from "./token-store"
export {
  PostgresPasskeyCredentialStore,
  type PostgresPasskeyCredentialStoreOptions,
} from "./passkey-credential-store"
