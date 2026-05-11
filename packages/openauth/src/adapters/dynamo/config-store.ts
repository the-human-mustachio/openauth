/**
 * DynamoDB `ConfigStore`. `pk="tenant"`, `sk=<tenantId>`. Read-eventual
 * by default (config is read-heavy, write-rare); the invalidation hook
 * fires on every `putTenantConfig` so in-process caches drop stale values
 * immediately.
 */
import type { ConfigStore } from "../../ports/config-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantConfig, TenantId } from "../../types/tenant"

import type { DynamoExecutor } from "./client"

export type DynamoConfigStoreOptions = {
  exec: DynamoExecutor
}

export class DynamoConfigStore implements ConfigStore {
  #exec: DynamoExecutor
  #listeners = new Set<(id: TenantId) => void>()

  constructor(opts: DynamoConfigStoreOptions) {
    this.#exec = opts.exec
  }

  async getTenantConfig(id: TenantId): Promise<Result<TenantConfig>> {
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.get({
        key: { pk: "tenant", sk: id },
        consistentRead: false,
      })
    } catch (e) {
      return err(authError.internalError("getTenantConfig: get failed", e))
    }
    if (!row) {
      return err(authError.tenantNotFound(`tenant "${id}" not found`, id))
    }
    return ok(parseConfig(row.config))
  }

  async putTenantConfig(config: TenantConfig): Promise<Result<void>> {
    try {
      await this.#exec.put({
        item: {
          pk: "tenant",
          sk: config.id,
          config: JSON.stringify(config),
          updated_at: Date.now(),
        },
      })
    } catch (e) {
      return err(authError.internalError("putTenantConfig: put failed", e))
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

function parseConfig(raw: unknown): TenantConfig {
  if (typeof raw === "string") return JSON.parse(raw) as TenantConfig
  return raw as TenantConfig
}
