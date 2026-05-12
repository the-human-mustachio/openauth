/**
 * Postgres `ConfigStore`. JSONB blob keyed by tenant id. Invalidation hook
 * fires on every `putTenantConfig` so any in-process cache built on top of
 * this adapter drops the stale value before the write resolves.
 */
import type { ConfigStore } from "../../ports/config-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantConfig, TenantId } from "../../types/tenant"

import type { PostgresExecutor } from "./executor"

export type PostgresConfigStoreOptions = {
  exec: PostgresExecutor
  clock?: () => number
}

export class PostgresConfigStore implements ConfigStore {
  #exec: PostgresExecutor
  #clock: () => number
  #listeners = new Set<(id: TenantId) => void>()

  constructor(opts: PostgresConfigStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async getTenantConfig(id: TenantId): Promise<Result<TenantConfig>> {
    let row: { config: unknown } | undefined
    try {
      const result = await this.#exec.query<{ config: unknown }>(
        `SELECT config FROM openauth_tenants WHERE id = $1`,
        [id],
      )
      row = result.rows[0]
    } catch (e) {
      return err(authError.internalError("getTenantConfig: query failed", e))
    }
    if (!row) {
      return err(authError.tenantNotFound(`tenant "${id}" not found`, id))
    }
    const config =
      typeof row.config === "string"
        ? (JSON.parse(row.config) as TenantConfig)
        : (row.config as TenantConfig)
    return ok(config)
  }

  async putTenantConfig(config: TenantConfig): Promise<Result<void>> {
    try {
      await this.#exec.query(
        `INSERT INTO openauth_tenants (id, config, updated_at)
         VALUES ($1, $2::jsonb, $3)
         ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, updated_at = EXCLUDED.updated_at`,
        [config.id, JSON.stringify(config), this.#clock()],
      )
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
