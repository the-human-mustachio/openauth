/**
 * Minimal `DurableObjectStorage` shape the adapter depends on. Defined
 * locally so the adapter is testable without a real Workers runtime and so
 * it stays compatible with both legacy and current versions of
 * `@cloudflare/workers-types`.
 *
 * Real `DurableObjectStorage` instances satisfy this interface — pass
 * `this.ctx.storage` directly.
 */
export type DurableObjectTransactionLike = {
  get<T>(key: string): Promise<T | undefined>
  put<T>(key: string, value: T): Promise<void>
  delete(key: string): Promise<boolean>
}

export type DurableObjectStorageLike = DurableObjectTransactionLike & {
  /**
   * Run a closure atomically. On any DO, all operations within `closure`
   * see a consistent snapshot of storage; the closure's return value is
   * resolved after the writes are durable.
   */
  transaction<T>(
    closure: (txn: DurableObjectTransactionLike) => Promise<T>,
  ): Promise<T>
}
