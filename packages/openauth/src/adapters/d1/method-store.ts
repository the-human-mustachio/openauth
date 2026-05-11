/**
 * D1 `MethodStore`. `(tenant_id, method_id)` composite key, JSON-as-TEXT
 * config blob.
 */
import type { MethodStore } from "../../ports/method-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { MethodConfig, TenantId } from "../../types/tenant"

import type { AnyD1Database } from "./types"

export type D1MethodStoreOptions = {
  db: AnyD1Database
  clock?: () => number
}

export class D1MethodStore implements MethodStore {
  #db: AnyD1Database
  #clock: () => number

  constructor(opts: D1MethodStoreOptions) {
    this.#db = opts.db
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async listMethods(tenantId: TenantId): Promise<Result<MethodConfig[]>> {
    try {
      const result = await this.#db
        .prepare(
          `SELECT config FROM openauth_methods WHERE tenant_id = ?1 ORDER BY method_id`,
        )
        .bind(tenantId)
        .all<{ config: string }>()
      return ok(result.results.map((r) => JSON.parse(r.config) as MethodConfig))
    } catch (e) {
      return err(authError.internalError("listMethods: query failed", e))
    }
  }

  async getMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<MethodConfig>> {
    let row: { config: string } | null
    try {
      row = await this.#db
        .prepare(
          `SELECT config FROM openauth_methods WHERE tenant_id = ?1 AND method_id = ?2`,
        )
        .bind(tenantId, methodId)
        .first<{ config: string }>()
    } catch (e) {
      return err(authError.internalError("getMethodConfig: query failed", e))
    }
    if (!row) {
      return err(
        authError.methodNotFound(
          `method "${methodId}" not found for tenant "${tenantId}"`,
          { methodId },
        ),
      )
    }
    return ok(JSON.parse(row.config) as MethodConfig)
  }

  async putMethodConfig(
    tenantId: TenantId,
    method: MethodConfig,
  ): Promise<Result<void>> {
    try {
      await this.#db
        .prepare(
          `INSERT INTO openauth_methods (tenant_id, method_id, config, updated_at) VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(tenant_id, method_id) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at`,
        )
        .bind(tenantId, method.id, JSON.stringify(method), this.#clock())
        .run()
    } catch (e) {
      return err(authError.internalError("putMethodConfig: insert failed", e))
    }
    return ok(undefined)
  }

  async deleteMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<void>> {
    try {
      await this.#db
        .prepare(
          `DELETE FROM openauth_methods WHERE tenant_id = ?1 AND method_id = ?2`,
        )
        .bind(tenantId, methodId)
        .run()
    } catch (e) {
      return err(authError.internalError("deleteMethodConfig: delete failed", e))
    }
    return ok(undefined)
  }
}
