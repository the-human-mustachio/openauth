/**
 * Cloudflare KV `ConfigStore`. JSON-serialized tenant config under
 * `tenant:<id>`. Per `ports/CONSISTENCY.md`, KV is **only** acceptable for
 * read-eventual paths — tenant config qualifies (read-heavy, write-rare,
 * 60s bounded staleness is fine). Invalidation hook fires on every
 * `putTenantConfig`.
 *
 * KV reads honor the cache hint via `cacheTtl` in the get options. The
 * 60-second default matches the bounded-staleness contract.
 */
import type { ConfigStore } from "../../ports/config-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantConfig, TenantId } from "../../types/tenant"

import type { KVNamespaceLike } from "./types"

const TENANT_PREFIX = "tenant:"

export type KvConfigStoreOptions = {
  kv: KVNamespaceLike
}

export class KvConfigStore implements ConfigStore {
  #kv: KVNamespaceLike
  #listeners = new Set<(id: TenantId) => void>()

  constructor(opts: KvConfigStoreOptions) {
    this.#kv = opts.kv
  }

  async getTenantConfig(id: TenantId): Promise<Result<TenantConfig>> {
    let raw: string | null
    try {
      raw = await this.#kv.get(TENANT_PREFIX + id)
    } catch (e) {
      return err(authError.internalError("getTenantConfig: kv.get failed", e))
    }
    if (!raw) {
      return err(authError.tenantNotFound(`tenant "${id}" not found`, id))
    }
    return ok(JSON.parse(raw) as TenantConfig)
  }

  async putTenantConfig(config: TenantConfig): Promise<Result<void>> {
    try {
      await this.#kv.put(TENANT_PREFIX + config.id, JSON.stringify(config))
    } catch (e) {
      return err(authError.internalError("putTenantConfig: kv.put failed", e))
    }
    for (const fn of this.#listeners) {
      try {
        fn(config.id)
      } catch {}
    }
    return ok(undefined)
  }

  onInvalidate(handler: (id: TenantId) => void): void {
    this.#listeners.add(handler)
  }
}
