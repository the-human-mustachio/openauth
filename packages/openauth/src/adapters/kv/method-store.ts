/**
 * Cloudflare KV `MethodStore`. Per-method JSON under
 * `method:<tenantId>:<methodId>`. `listMethods` uses the KV `list` cursor +
 * follow-up `get` per key — fine for the read-rare console workflow but
 * not for hot per-request paths (the IdP framework caches `MethodConfig`
 * via `MethodCache` in-process).
 */
import type { MethodStore } from "../../ports/method-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { MethodConfig, TenantId } from "../../types/tenant"

import type { KVNamespaceLike } from "./types"

const methodKey = (tenantId: TenantId, methodId: string) =>
  `method:${tenantId}:${methodId}`
const methodPrefix = (tenantId: TenantId) => `method:${tenantId}:`

export type KvMethodStoreOptions = {
  kv: KVNamespaceLike
}

export class KvMethodStore implements MethodStore {
  #kv: KVNamespaceLike

  constructor(opts: KvMethodStoreOptions) {
    this.#kv = opts.kv
  }

  async listMethods(tenantId: TenantId): Promise<Result<MethodConfig[]>> {
    const prefix = methodPrefix(tenantId)
    const methods: MethodConfig[] = []
    let cursor: string | null | undefined
    try {
      do {
        const page = await this.#kv.list({ prefix, cursor: cursor ?? null })
        for (const k of page.keys) {
          const value = await this.#kv.get(k.name)
          if (value) methods.push(JSON.parse(value) as MethodConfig)
        }
        cursor = page.list_complete ? undefined : page.cursor
      } while (cursor)
    } catch (e) {
      return err(authError.internalError("listMethods: kv.list failed", e))
    }
    // KV doesn't guarantee list order; the conformance suite sorts by id.
    methods.sort((a, b) => a.id.localeCompare(b.id))
    return ok(methods)
  }

  async getMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<MethodConfig>> {
    let raw: string | null
    try {
      raw = await this.#kv.get(methodKey(tenantId, methodId))
    } catch (e) {
      return err(authError.internalError("getMethodConfig: kv.get failed", e))
    }
    if (!raw) {
      return err(
        authError.methodNotFound(
          `method "${methodId}" not found for tenant "${tenantId}"`,
          { methodId },
        ),
      )
    }
    return ok(JSON.parse(raw) as MethodConfig)
  }

  async putMethodConfig(
    tenantId: TenantId,
    method: MethodConfig,
  ): Promise<Result<void>> {
    try {
      await this.#kv.put(methodKey(tenantId, method.id), JSON.stringify(method))
    } catch (e) {
      return err(authError.internalError("putMethodConfig: kv.put failed", e))
    }
    return ok(undefined)
  }

  async deleteMethodConfig(
    tenantId: TenantId,
    methodId: string,
  ): Promise<Result<void>> {
    try {
      await this.#kv.delete(methodKey(tenantId, methodId))
    } catch (e) {
      return err(
        authError.internalError("deleteMethodConfig: kv.delete failed", e),
      )
    }
    return ok(undefined)
  }
}
