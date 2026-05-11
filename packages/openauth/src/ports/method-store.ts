/**
 * `MethodStore` — per-tenant `MethodConfig` lookup.
 *
 * This is a subset of `ConfigStore` exposed as a separate port for two
 * reasons:
 *  1. Adapters may want to back `MethodStore` with a more frequently
 *     invalidated cache than the full tenant config.
 *  2. The management console can update auth-method config independently
 *     of other tenant-level fields.
 *
 * Consistency: same as `ConfigStore` — eventual + bounded staleness
 * (TTL ≤ 60 s). Invalidation hook fires on update.
 */
import type { Result } from "../types/result.js"
import type { MethodConfig, TenantId } from "../types/tenant.js"

export type MethodStore = {
  /** All method instances configured for a tenant (enabled and disabled). */
  listMethods(tenantId: TenantId): Promise<Result<MethodConfig[]>>

  /**
   * Look up a single method instance by tenant-local id. Returns
   * `method_not_found` if `methodId` does not exist in this tenant.
   */
  getMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<MethodConfig>>

  /** Persist (create or update) a method instance. Triggers invalidation. */
  putMethodConfig(
    tenantId: TenantId,
    method: MethodConfig,
  ): Promise<Result<void>>

  /** Delete a method instance. Tokens issued by it remain valid until expiry. */
  deleteMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<void>>
}
