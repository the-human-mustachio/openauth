/**
 * `ConfigStore` — tenant configuration lookup.
 *
 * Consistency contract: **eventual + bounded staleness (TTL ≤ 60 s).** This
 * is a read-heavy, write-rare path; Cloudflare KV / read replicas are
 * acceptable. Invalidation hook fires immediately on update so callers can
 * drop stale entries earlier than TTL.
 *
 * See `ports/CONSISTENCY.md` for the full table.
 */
import type { Result } from "../types/result.js"
import type { TenantConfig, TenantId } from "../types/tenant.js"

export type ConfigStore = {
  /**
   * Look up a tenant's full config. Returns `tenant_not_found` if the id is
   * unknown. Implementations should cache aggressively (TTL ≤ 60 s).
   */
  getTenantConfig(id: TenantId): Promise<Result<TenantConfig>>

  /**
   * Persist (create or update) a tenant's config. Implementations must
   * trigger invalidation of any cached value for `id` before resolving so
   * a subsequent `getTenantConfig` returns the new value.
   */
  putTenantConfig(config: TenantConfig): Promise<Result<void>>

  /**
   * Optional: signal to in-process caches that a tenant's config has been
   * invalidated externally (e.g. via the management console). Adapters that
   * don't expose cross-process invalidation may omit this.
   */
  onInvalidate?(handler: (id: TenantId) => void): void
}
