/**
 * DynamoDB `MethodStore`. `pk="tenant-methods:<tenantId>"`, `sk=<methodId>`.
 * Co-locating methods per-tenant lets `listMethods` use a single Query.
 */
import type { MethodStore } from "../../ports/method-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { MethodConfig, TenantId } from "../../types/tenant"

import type { DynamoExecutor } from "./client"

const partitionKey = (tenantId: TenantId) => `tenant-methods:${tenantId}`

export type DynamoMethodStoreOptions = {
  exec: DynamoExecutor
}

export class DynamoMethodStore implements MethodStore {
  #exec: DynamoExecutor

  constructor(opts: DynamoMethodStoreOptions) {
    this.#exec = opts.exec
  }

  async listMethods(tenantId: TenantId): Promise<Result<MethodConfig[]>> {
    let items: Record<string, unknown>[]
    try {
      items = await this.#exec.query({
        pk: partitionKey(tenantId),
        consistentRead: false,
      })
    } catch (e) {
      return err(authError.internalError("listMethods: query failed", e))
    }
    const methods = items
      .map((r) => parseMethod(r.config))
      .sort((a, b) => a.id.localeCompare(b.id))
    return ok(methods)
  }

  async getMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<MethodConfig>> {
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.get({
        key: { pk: partitionKey(tenantId), sk: methodId },
        consistentRead: false,
      })
    } catch (e) {
      return err(authError.internalError("getMethodConfig: get failed", e))
    }
    if (!row) {
      return err(
        authError.methodNotFound(
          `method "${methodId}" not found for tenant "${tenantId}"`,
          { methodId },
        ),
      )
    }
    return ok(parseMethod(row.config))
  }

  async putMethodConfig(
    tenantId: TenantId,
    method: MethodConfig,
  ): Promise<Result<void>> {
    try {
      await this.#exec.put({
        item: {
          pk: partitionKey(tenantId),
          sk: method.id,
          config: JSON.stringify(method),
          updated_at: Date.now(),
        },
      })
    } catch (e) {
      return err(authError.internalError("putMethodConfig: put failed", e))
    }
    return ok(undefined)
  }

  async deleteMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<void>> {
    try {
      await this.#exec.delete({
        key: { pk: partitionKey(tenantId), sk: methodId },
      })
    } catch (e) {
      return err(authError.internalError("deleteMethodConfig: delete failed", e))
    }
    return ok(undefined)
  }
}

function parseMethod(raw: unknown): MethodConfig {
  if (typeof raw === "string") return JSON.parse(raw) as MethodConfig
  return raw as MethodConfig
}
