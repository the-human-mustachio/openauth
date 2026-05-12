/**
 * Cloudflare Durable Objects adapters.
 *
 * Durable Objects are an excellent fit for `SessionStore` (flow records)
 * because every operation on a single DO instance is serialized — atomic
 * delete-on-read comes for free with `storage.transaction`. Per
 * `ports/CONSISTENCY.md`, DOs are also acceptable for `TokenStore` in
 * deployments that don't run D1.
 *
 * The adapter is supplied a `DurableObjectStorage` directly (`this.ctx.storage`
 * from inside a DO class). Users wire their own DO class around the adapter
 * and forward RPC / fetch calls to the methods. See the JSDoc on
 * `DurableObjectSessionStore` for the canonical wiring pattern.
 */
export {
  DurableObjectSessionStore,
  type DurableObjectSessionStoreOptions,
} from "./session-store"

export type {
  DurableObjectStorageLike,
  DurableObjectTransactionLike,
} from "./types"
