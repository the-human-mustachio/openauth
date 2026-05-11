/**
 * D1 `ConfigStore`. JSON-as-TEXT, eventual-consistency reads acceptable per
 * `ports/CONSISTENCY.md`. Invalidation hook fires on every put.
 */
import type { ConfigStore } from "../../ports/config-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantConfig, TenantId } from "../../types/tenant"

import type { AnyD1Database } from "./types"

export type D1ConfigStoreOptions = {
  db: AnyD1Database
  clock?: () => number
}

export class D1ConfigStore implements ConfigStore {
  #db: AnyD1Database
  #clock: () => number
  #listeners = new Set<(id: TenantId) => void>()

  constructor(opts: D1ConfigStoreOptions) {
    this.#db = opts.db
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async getTenantConfig(id: TenantId): Promise<Result<TenantConfig>> {
    let row: { config: string } | null
    try {
      row = await this.#db
        .prepare(`SELECT config FROM openauth_tenants WHERE id = ?1`)
        .bind(id)
        .first<{ config: string }>()
    } catch (e) {
      return err(authError.internalError("getTenantConfig: query failed", e))
    }
    if (!row) {
      return err(authError.tenantNotFound(`tenant "${id}" not found`, id))
    }
    return ok(JSON.parse(row.config) as TenantConfig)
  }

  async putTenantConfig(config: TenantConfig): Promise<Result<void>> {
    try {
      await this.#db
        .prepare(
          `INSERT INTO openauth_tenants (id, config, updated_at) VALUES (?1, ?2, ?3)
           ON CONFLICT(id) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at`,
        )
        .bind(config.id, JSON.stringify(config), this.#clock())
        .run()
    } catch (e) {
      return err(authError.internalError("putTenantConfig: insert failed", e))
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
