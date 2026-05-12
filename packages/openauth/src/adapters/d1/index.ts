/**
 * Cloudflare D1 adapter set.
 *
 * Per AD8 + the D1 read-replication caveat in `ports/CONSISTENCY.md`, every
 * operation on the security-critical paths (`TokenStore`, `SessionStore`)
 * wraps its statement in `db.withSession("first-primary")` so reads observe
 * the latest write. Read-eventual paths (`ConfigStore`, `KeyStore.signingKeys`,
 * `MethodStore`, `AuditLog`) use the plain `D1Database` and benefit from
 * replica reads when available.
 *
 * Feature detection — if the `D1Database` runtime predates the Sessions API,
 * the helper degrades to plain `prepare`. This keeps the adapter compatible
 * with older Workers runtimes and test shims (bun:sqlite via the
 * `test/adapters/d1.test.ts` harness) at the cost of relying on
 * single-replica consistency in those environments.
 *
 * @example
 *   export default {
 *     async fetch(req, env) {
 *       const keyStore = new D1KeyStore({ db: env.AUTH })
 *       const tokenStore = new D1TokenStore({ db: env.AUTH, keyStore })
 *       // ...
 *     }
 *   }
 */
export { D1AuditLog, type D1AuditLogOptions } from "./audit-log"
export { D1ConfigStore, type D1ConfigStoreOptions } from "./config-store"
export { D1KeyStore, type D1KeyStoreOptions } from "./key-store"
export { D1MethodStore, type D1MethodStoreOptions } from "./method-store"
export { D1SessionStore, type D1SessionStoreOptions } from "./session-store"
export { D1TokenStore, type D1TokenStoreOptions } from "./token-store"

export { INITIAL_SCHEMA_SQL, migrate } from "./migrations"
export { isSessionsCapable, primarySession } from "./session"
export {
  type AnyD1Database,
  type D1DatabaseSession,
  type D1DatabaseWithSessions,
  type D1SessionBookmark,
  type D1SessionConstraint,
} from "./types"
