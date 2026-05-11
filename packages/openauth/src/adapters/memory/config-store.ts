/**
 * In-memory `ConfigStore`. Single-process; trivially satisfies the
 * eventual + bounded-staleness contract (it's strong, which is a superset).
 */
import type { ConfigStore } from "../../ports/config-store"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import { authError } from "../../types/error"
import type { TenantConfig, TenantId } from "../../types/tenant"

export type MemoryConfigStoreOptions = {
  /** Seed tenants — useful for tests. */
  seed?: ReadonlyArray<TenantConfig>
}

export class MemoryConfigStore implements ConfigStore {
  #tenants = new Map<TenantId, TenantConfig>()
  #listeners = new Set<(id: TenantId) => void>()

  constructor(opts: MemoryConfigStoreOptions = {}) {
    for (const t of opts.seed ?? []) this.#tenants.set(t.id, t)
  }

  async getTenantConfig(id: TenantId): Promise<Result<TenantConfig>> {
    const t = this.#tenants.get(id)
    if (!t) {
      return err(authError.tenantNotFound(`tenant "${id}" not found`, id))
    }
    return ok(t)
  }

  async putTenantConfig(config: TenantConfig): Promise<Result<void>> {
    this.#tenants.set(config.id, config)
    for (const fn of this.#listeners) fn(config.id)
    return ok(undefined)
  }

  onInvalidate(handler: (id: TenantId) => void): void {
    this.#listeners.add(handler)
  }
}
