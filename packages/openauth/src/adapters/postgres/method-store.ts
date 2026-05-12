/**
 * Postgres `MethodStore`. `(tenant_id, method_id)` composite key, JSONB
 * `config` column for the method-config blob.
 */
import type { MethodStore } from "../../ports/method-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { MethodConfig, TenantId } from "../../types/tenant"

import type { PostgresExecutor } from "./executor"

export type PostgresMethodStoreOptions = {
  exec: PostgresExecutor
  clock?: () => number
}

export class PostgresMethodStore implements MethodStore {
  #exec: PostgresExecutor
  #clock: () => number

  constructor(opts: PostgresMethodStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async listMethods(tenantId: TenantId): Promise<Result<MethodConfig[]>> {
    try {
      const result = await this.#exec.query<{ config: unknown }>(
        `SELECT config FROM openauth_methods WHERE tenant_id = $1 ORDER BY method_id`,
        [tenantId],
      )
      const methods = result.rows.map((r) => parseConfig(r.config))
      return ok(methods)
    } catch (e) {
      return err(authError.internalError("listMethods: query failed", e))
    }
  }

  async getMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<MethodConfig>> {
    let row: { config: unknown } | undefined
    try {
      const result = await this.#exec.query<{ config: unknown }>(
        `SELECT config FROM openauth_methods WHERE tenant_id = $1 AND method_id = $2`,
        [tenantId, methodId],
      )
      row = result.rows[0]
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
    return ok(parseConfig(row.config))
  }

  async putMethodConfig(
    tenantId: TenantId,
    method: MethodConfig,
  ): Promise<Result<void>> {
    try {
      await this.#exec.query(
        `INSERT INTO openauth_methods (tenant_id, method_id, config, updated_at)
         VALUES ($1, $2, $3::jsonb, $4)
         ON CONFLICT (tenant_id, method_id) DO UPDATE
           SET config = EXCLUDED.config, updated_at = EXCLUDED.updated_at`,
        [tenantId, method.id, JSON.stringify(method), this.#clock()],
      )
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
      await this.#exec.query(
        `DELETE FROM openauth_methods WHERE tenant_id = $1 AND method_id = $2`,
        [tenantId, methodId],
      )
    } catch (e) {
      return err(
        authError.internalError("deleteMethodConfig: delete failed", e),
      )
    }
    return ok(undefined)
  }
}

function parseConfig(raw: unknown): MethodConfig {
  if (typeof raw === "string") return JSON.parse(raw) as MethodConfig
  return raw as MethodConfig
}
