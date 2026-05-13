/**
 * Shared deps + per-request context for the HTTP layer.
 *
 * `HttpDeps` is constructed once by `createIdP` and threaded through every
 * handler. `HttpVars` is the per-request Hono-variable shape: tenant
 * resolution, parsed cookies, optional recovery info from the callback chain.
 */
import type { Context } from "hono"

import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { MethodStore } from "../ports/method-store"
import type { SessionStore } from "../ports/session-store"
import type { TokenStore } from "../ports/token-store"
import type { MethodCache } from "../domain/method-cache"
import type { AuthError } from "../types/error"
import type {
  ExchangeAudience,
  PersistUpstreamTokens,
  RegisterClient,
  RenderPicker,
  SuccessMapInput,
} from "../types/idp"
import type { Result } from "../types/result"
import type { SubjectClaim } from "../types/subject"
import type {
  StateKeyRing,
  TenantContext,
  TenantId,
  TenantRecovery,
} from "../types/tenant"

import type { CookieDefaults } from "./cookies"

/** Long-lived deps the HTTP layer shares across requests. */
export type HttpDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  sessionStore: SessionStore
  keyStore: KeyStore
  methodStore?: MethodStore
  auditLog?: AuditLog
  methodCache: MethodCache
  stateKeys: StateKeyRing
  /** Resolves the issuer URL — string or per-request function. */
  resolveIssuer: (req: Request) => string
  /** Optional partitioned-host helper (recovery #2). */
  callbackHostFor?: (tenantId: TenantId) => string
  resolveTenant: (req: Request) => Promise<Result<TenantId, AuthError>>
  success: (input: SuccessMapInput) => Promise<SubjectClaim>
  persistUpstreamTokens?: PersistUpstreamTokens
  exchangeAudience?: ExchangeAudience
  renderPicker?: RenderPicker
  registerClient?: RegisterClient
  /** Builds `TenantContext.request.custom` for every request. See `IdPOptions.buildCustomContext`. */
  buildCustomContext?: (
    req: Request,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>
  clock: () => number
  cookieDefaults: CookieDefaults
  /** See `IdPOptions.customScopeClaims`. */
  customScopeClaims?: Record<string, ReadonlyArray<string>>
}

/** Per-request variables populated by middleware. */
export type HttpVars = {
  /** Parsed `Cookie:` header. */
  cookies: Map<string, string>
  /** Populated by the tenant middleware. May be `null` for unauthenticated public endpoints. */
  tenant: TenantContext | null
  /** Outcome of the callback-recovery chain on `/cb/*` requests. */
  recovery: TenantRecovery | null
  /** Issuer URL for this request — pre-resolved by middleware. */
  issuerUrl: string
}

export type HttpEnv = {
  Variables: HttpVars
}

export type HttpContext = Context<HttpEnv>

/** Convenience: build the initial `HttpVars` value for a request. */
export function initialVars(
  issuerUrl: string,
  cookies: Map<string, string>,
): HttpVars {
  return { cookies, tenant: null, recovery: null, issuerUrl }
}
