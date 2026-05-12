/**
 * In-memory `MethodStore`. Per-tenant `Map<methodId, MethodConfig>`. Single
 * process so the eventual + bounded-staleness contract is trivially satisfied.
 *
 * `MethodStore` is optional in the IdP — when omitted, the framework falls
 * back to slicing `MethodConfig[]` out of `ConfigStore.getTenantConfig`. The
 * memory adapter still ships so the conformance suite has a baseline.
 */
import type { MethodStore } from "../../ports/method-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { MethodConfig, TenantId } from "../../types/tenant"

export type MemoryMethodStoreOptions = {
  seed?: ReadonlyArray<{
    tenantId: TenantId
    methods: ReadonlyArray<MethodConfig>
  }>
}

export class MemoryMethodStore implements MethodStore {
  #byTenant = new Map<TenantId, Map<string, MethodConfig>>()

  constructor(opts: MemoryMethodStoreOptions = {}) {
    for (const seed of opts.seed ?? []) {
      const inner = new Map<string, MethodConfig>()
      for (const m of seed.methods) inner.set(m.id, m)
      this.#byTenant.set(seed.tenantId, inner)
    }
  }

  async listMethods(tenantId: TenantId): Promise<Result<MethodConfig[]>> {
    const inner = this.#byTenant.get(tenantId)
    return ok(inner ? Array.from(inner.values()) : [])
  }

  async getMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<MethodConfig>> {
    const inner = this.#byTenant.get(tenantId)
    const m = inner?.get(methodId)
    if (!m) {
      return err(
        authError.methodNotFound(
          `method "${methodId}" not found for tenant "${tenantId}"`,
          { methodId },
        ),
      )
    }
    return ok(m)
  }

  async putMethodConfig(
    tenantId: TenantId,
    method: MethodConfig,
  ): Promise<Result<void>> {
    let inner = this.#byTenant.get(tenantId)
    if (!inner) {
      inner = new Map<string, MethodConfig>()
      this.#byTenant.set(tenantId, inner)
    }
    inner.set(method.id, method)
    return ok(undefined)
  }

  async deleteMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<void>> {
    this.#byTenant.get(tenantId)?.delete(methodId)
    return ok(undefined)
  }
}
