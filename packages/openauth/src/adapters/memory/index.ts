/**
 * In-memory adapter set. Map-backed. Suitable for tests and single-instance
 * dev. Trivially satisfies all consistency contracts in
 * `ports/CONSISTENCY.md` because there's no concurrent process / replica
 * lag.
 */
export { MemoryAuditLog, type StoredAuditEvent } from "./audit-log"
export {
  MemoryConfigStore,
  type MemoryConfigStoreOptions,
} from "./config-store"
export { MemoryKeyStore, type MemoryKeyStoreOptions } from "./key-store"
export {
  MemoryMethodStore,
  type MemoryMethodStoreOptions,
} from "./method-store"
export {
  MemorySessionStore,
  type MemorySessionStoreOptions,
} from "./session-store"
export { MemoryTokenStore, type MemoryTokenStoreOptions } from "./token-store"
export { realClock, type Clock } from "./clock"
