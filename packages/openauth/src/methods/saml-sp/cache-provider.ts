/**
 * `@node-saml/node-saml` `CacheProvider` backed by `methodScratch`.
 *
 * node-saml tracks outstanding `AuthnRequest` IDs through a
 * `CacheProvider`: `saveAsync(requestId, marker)` when the request is
 * generated, then `getAsync` + `removeAsync` during response
 * validation to enforce `InResponseTo` (defeats unsolicited /
 * replayed Responses on the SP-initiated path).
 *
 * The default in-memory provider is single-process only. We back it
 * with `MethodContext.methodScratch`, which is already scoped per
 * `(tenantId, methodId)` and shared across instances via the
 * `SessionStore` adapter — so an AuthnRequest minted on one node
 * validates on another.
 *
 * `methodScratch.get` returning `unknown_state` (missing / expired)
 * maps to `null`, which is exactly node-saml's "unknown request id"
 * signal.
 */
import type { MethodScratch } from "../../types/method"

import { isOk } from "../../types/result"

type CacheItem = { value: string; createdAt: number }
type NodeSamlCacheProvider = {
  saveAsync(key: string, value: string): Promise<CacheItem | null>
  getAsync(key: string): Promise<string | null>
  removeAsync(key: string | null): Promise<string | null>
}

/** Key namespace inside the (already tenant/method-scoped) scratch. */
const KEY_PREFIX = "saml-inresponseto:"

/**
 * @param scratch  Per-request `MethodContext.methodScratch`.
 * @param ttlMs    How long an outstanding request id stays valid. Should
 *                  comfortably exceed the slowest realistic IdP login
 *                  (the flow record itself expires independently).
 */
export function methodScratchCacheProvider(
  scratch: MethodScratch,
  ttlMs: number,
): NodeSamlCacheProvider {
  return {
    async saveAsync(key, value) {
      const createdAt = Date.now()
      const item: CacheItem = { value, createdAt }
      const r = await scratch.put(
        `${KEY_PREFIX}${key}`,
        JSON.stringify(item),
        ttlMs,
      )
      // node-saml treats a null return as "could not cache" and fails
      // the request generation loudly — which is what we want if the
      // backing store is unavailable.
      return isOk(r) ? item : null
    },

    async getAsync(key) {
      const r = await scratch.get(`${KEY_PREFIX}${key}`)
      if (!isOk(r)) return null
      try {
        const item = JSON.parse(r.value) as CacheItem
        return item.value
      } catch {
        return null
      }
    },

    async removeAsync(key) {
      if (key === null) return null
      const r = await scratch.delete(`${KEY_PREFIX}${key}`)
      return isOk(r) ? key : null
    },
  }
}
