/**
 * Minimal `KVNamespace` shape the adapter depends on. Pinned locally so the
 * adapter is testable without a real Workers runtime.
 *
 * Real `KVNamespace` instances satisfy this interface — pass `env.AUTH_KV`
 * directly.
 */
export type KVNamespaceLike = {
  get(key: string): Promise<string | null>
  get<T>(key: string, type: "json"): Promise<T | null>
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number; expiration?: number },
  ): Promise<void>
  delete(key: string): Promise<void>
  list(options?: {
    prefix?: string
    cursor?: string | null
    limit?: number
  }): Promise<{
    keys: Array<{ name: string }>
    list_complete: boolean
    cursor?: string
  }>
}
