/**
 * Cloudflare KV adapters — **restricted use only**.
 *
 * Per `ports/CONSISTENCY.md`, KV's eventual consistency disqualifies it as
 * a backing store for `TokenStore` (auth codes, refresh tokens) and
 * `SessionStore` (flow records). Use D1 / Durable Objects / Postgres /
 * DynamoDB for those. KV remains a great fit for the read-eventual paths
 * exposed in this package:
 *
 *  - `KvConfigStore` — tenant config blob keyed by id
 *  - `KvMethodStore` — per-tenant method configs
 *  - `KvAuditLog` — append-only audit events (low-volume only)
 *
 * Production users typically mix-and-match: KV for config + D1 for tokens
 * + Durable Objects for sessions.
 */
export { KvAuditLog, type KvAuditLogOptions } from "./audit-log"
export { KvConfigStore, type KvConfigStoreOptions } from "./config-store"
export { KvMethodStore, type KvMethodStoreOptions } from "./method-store"
export type { KVNamespaceLike } from "./types"
