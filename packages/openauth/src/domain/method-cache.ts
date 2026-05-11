/**
 * `MethodCache` — loads `AuthMethodFactory` builds per
 * `(tenantId, MethodConfig.id)` and caches the result.
 *
 * Responsibilities per plan §"Per-tenant config → typed method config":
 *  1. Look up the factory by `MethodConfig.kind`. Unknown kind → audit
 *     `unknown_method_kind`, treat instance as disabled.
 *  2. Validate `MethodConfig.config` against `factory.configSchema`.
 *     Failure → audit `invalid_method_config`, treat instance as disabled.
 *  3. Call `factory.build({ id, kind, tenantId, config })`. Verify the
 *     returned `AuthMethod` has `id` / `kind` matching the inputs. Mismatch
 *     → audit `factory_id_mismatch`, fail the load.
 *  4. Cache per `(tenantId, MethodConfig.id)`. The cache is in-process —
 *     TTL is governed by the `ConfigStore` invalidation hook in Phase 3+;
 *     in Phase 2 / tests, manual `invalidate(tenantId)` is sufficient.
 */
import type { AuditLog } from "../ports/audit-log"
import { authError, type AuthError } from "../types/error"
import type { AnyAuthMethodFactory, AuthMethod } from "../types/method"
import type { Result } from "../types/result"
import { err, ok } from "../types/result"
import type { MethodConfig, TenantConfig, TenantId } from "../types/tenant"

export type MethodCacheOptions = {
  factories: Record<string, AnyAuthMethodFactory>
  auditLog?: AuditLog
  /** Injectable clock for audit timestamps. */
  now: () => number
}

export class MethodCache {
  #factories: Record<string, AnyAuthMethodFactory>
  #auditLog?: AuditLog
  #now: () => number
  #cache = new Map<string, AuthMethod>()
  /** Negative-cache: instances we know are disabled (config invalid / unknown kind). */
  #disabled = new Set<string>()

  constructor(opts: MethodCacheOptions) {
    this.#factories = opts.factories
    this.#auditLog = opts.auditLog
    this.#now = opts.now
  }

  /**
   * Load (or fetch from cache) the `AuthMethod` for the given tenant +
   * tenant-local method instance id. Returns `method_not_found` for any
   * disabled / unknown / invalid-config path.
   */
  async resolve(
    tenant: TenantConfig,
    methodId: string,
  ): Promise<Result<AuthMethod, AuthError>> {
    const cacheKey = this.#key(tenant.id, methodId)
    const hit = this.#cache.get(cacheKey)
    if (hit) return ok(hit)
    if (this.#disabled.has(cacheKey)) {
      return err(
        authError.methodNotFound(
          `method "${methodId}" is disabled or has invalid config`,
          { methodId },
        ),
      )
    }

    const cfg = tenant.methods.find((m) => m.id === methodId)
    if (!cfg) {
      return err(
        authError.methodNotFound(`method "${methodId}" not configured`, {
          methodId,
        }),
      )
    }
    if (!cfg.enabled) {
      return err(
        authError.methodNotFound(`method "${methodId}" is disabled`, {
          methodId,
        }),
      )
    }

    const built = await this.#build(tenant.id, cfg)
    if (built.ok) {
      this.#cache.set(cacheKey, built.value)
    } else {
      this.#disabled.add(cacheKey)
    }
    return built
  }

  /** Drop cached instances for a tenant. Called on config invalidation. */
  invalidate(tenantId: TenantId, methodId?: string): void {
    if (methodId !== undefined) {
      const key = this.#key(tenantId, methodId)
      this.#cache.delete(key)
      this.#disabled.delete(key)
      return
    }
    for (const k of [...this.#cache.keys()]) {
      if (k.startsWith(`${tenantId}\0`)) this.#cache.delete(k)
    }
    for (const k of [...this.#disabled]) {
      if (k.startsWith(`${tenantId}\0`)) this.#disabled.delete(k)
    }
  }

  /** List all enabled methods for a tenant — used by method-selection UI. */
  async listAvailable(tenant: TenantConfig): Promise<AuthMethod[]> {
    const results: AuthMethod[] = []
    for (const cfg of tenant.methods) {
      if (!cfg.enabled) continue
      const m = await this.resolve(tenant, cfg.id)
      if (m.ok) results.push(m.value)
    }
    return results
  }

  async #build(
    tenantId: TenantId,
    cfg: MethodConfig,
  ): Promise<Result<AuthMethod, AuthError>> {
    const factory = this.#factories[cfg.kind]
    if (!factory) {
      await this.#audit({
        kind: "unknown_method_kind",
        tenantId,
        methodId: cfg.id,
        methodKind: cfg.kind,
        timestamp: this.#now(),
      })
      return err(
        authError.methodNotFound(
          `no factory registered for kind "${cfg.kind}"`,
          {
            methodId: cfg.id,
            methodKind: cfg.kind,
          },
        ),
      )
    }

    // Standard Schema v1: `validate` may return a Result or a Promise<Result>.
    // Successful Result has `{ value }`; failure has `{ issues }`.
    let parsed = factory.configSchema["~standard"].validate(cfg.config)
    if (parsed instanceof Promise) parsed = await parsed
    if ("issues" in parsed && parsed.issues) {
      await this.#audit({
        kind: "invalid_method_config",
        tenantId,
        methodId: cfg.id,
        methodKind: cfg.kind,
        errorPath: parsed.issues
          .map((issue) =>
            (issue.path ?? [])
              .map((segment) =>
                typeof segment === "object" ? String(segment.key) : String(segment),
              )
              .join("."),
          )
          .join(","),
        timestamp: this.#now(),
      })
      return err(
        authError.methodNotFound(
          `invalid method config for "${cfg.id}" (kind "${cfg.kind}")`,
          { methodId: cfg.id, methodKind: cfg.kind },
        ),
      )
    }

    let method: AuthMethod
    try {
      method = await factory.build({
        id: cfg.id,
        kind: cfg.kind,
        tenantId,
        config: parsed.value,
      })
    } catch (e) {
      return err(
        authError.internalError(
          `factory "${cfg.kind}" build threw for instance "${cfg.id}"`,
          e,
        ),
      )
    }

    if (method.id !== cfg.id || method.kind !== cfg.kind) {
      await this.#audit({
        kind: "factory_id_mismatch",
        tenantId,
        methodId: cfg.id,
        expectedKind: cfg.kind,
        actualKind: method.kind,
        timestamp: this.#now(),
      })
      return err(
        authError.internalError(
          `factory "${cfg.kind}" returned AuthMethod with id/kind ${method.id}/${method.kind}; expected ${cfg.id}/${cfg.kind}`,
        ),
      )
    }
    return ok(method)
  }

  #key(tenantId: TenantId, methodId: string): string {
    return `${tenantId}\0${methodId}`
  }

  async #audit(event: Parameters<AuditLog["log"]>[0]): Promise<void> {
    if (!this.#auditLog) return
    try {
      await this.#auditLog.log(event)
    } catch {
      // Audit failure must not break the hot path.
    }
  }
}
