/**
 * `/token` endpoint logic for `grant_type=refresh_token`.
 *
 * Rotation semantics (plan §"Cross-cutting Decisions" + §"Port consistency
 * contracts"):
 *
 *  - Refresh tokens rotate on every use. The presented token is consumed
 *    (CAS); a fresh refresh token is issued, keyed by the same `family`.
 *  - If the same token is presented a second time within the reuse window
 *    (default 60 s), the family is revoked and the request is rejected
 *    with `invalid_grant`. Audit: `refresh_reuse_detected`.
 *  - Outside the reuse window the row should be GC'd; presentation
 *    returns `invalid_grant` ("unknown token").
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { TokenStore } from "../ports/token-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr } from "../types/result"
import type { TenantContext } from "../types/tenant"
import type { TokenResponse } from "../types/token"

import { mintTokens } from "./token"

export type RefreshGrantRequest = {
  grantType: "refresh_token"
  refreshToken: string
  /** Optional per RFC 6749 — narrow scope. If absent, original scopes are reused. */
  scope?: string
  /** Confidential clients authenticate at /token. */
  clientId?: string
  clientSecret?: string
}

export type RefreshTokensDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  auditLog?: AuditLog
  issuerUrl: string
  clock: () => number
  /** Reuse-detection window (ms). Default 60 s. */
  reuseWindowMs?: number
  newRefreshToken?: () => string
}

export async function refreshTokens(
  req: RefreshGrantRequest,
  deps: RefreshTokensDeps,
): Promise<Result<TokenResponse, AuthError>> {
  const consumed = await deps.tokenStore.consumeRefresh(req.refreshToken, {
    reuseWindowMs: deps.reuseWindowMs,
  })
  if (isErr(consumed)) {
    if (consumed.error.description.includes("reuse detected")) {
      const parsed = parseReuseSignal(consumed.error.description)
      await audit(deps, {
        kind: "refresh_reuse_detected",
        tenantId: parsed.tenantId as never,
        clientId: req.clientId ?? "unknown",
        family: parsed.family,
        timestamp: deps.clock(),
      })
    }
    return err(consumed.error)
  }
  const payload = consumed.value

  const tenantCfg = await deps.configStore.getTenantConfig(payload.tenantId)
  if (isErr(tenantCfg)) return err(tenantCfg.error)

  // Narrow scope if requested (must be subset of original).
  const requestedScopes = req.scope
    ? req.scope.split(" ").filter(Boolean)
    : payload.scopes
  for (const s of requestedScopes) {
    if (!payload.scopes.includes(s)) {
      return err(
        authError.invalidScope(
          `requested scope "${s}" not granted by original refresh token`,
        ),
      )
    }
  }

  const tenant: TenantContext = {
    id: payload.tenantId,
    config: tenantCfg.value,
    request: { raw: new Request("about:blank"), custom: {} },
  }

  return mintTokens({
    tenant,
    claim: payload.claim,
    payload: {
      tenantId: payload.tenantId,
      clientId: payload.clientId,
      methodId: "refresh",
      methodKind: "refresh",
      scopes: requestedScopes,
      audience: payload.audience,
    },
    family: payload.family,
    deps,
  }).then(async (result) => {
    if (result.ok) {
      await audit(deps, {
        kind: "token_refreshed",
        tenantId: payload.tenantId,
        clientId: payload.clientId,
        subjectId: payload.subjectId,
        family: payload.family,
        timestamp: deps.clock(),
      })
    }
    return result
  })
}

/**
 * Parse the reuse-detection hint the `TokenStore` adapter is contractually
 * allowed to stamp into its `invalid_grant` description. Format:
 * `... (family=<id>,tenant=<id>,subject=<id>)`. Adapters that don't follow
 * this convention surface `"unknown"` for those fields — the audit event
 * still fires but with reduced fidelity.
 */
function parseReuseSignal(description: string): {
  family: string
  tenantId: string
  subjectId: string
} {
  const m = description.match(/family=([^,)]+),tenant=([^,)]+),subject=([^)]+)/)
  if (!m) {
    return { family: "unknown", tenantId: "unknown", subjectId: "unknown" }
  }
  return { family: m[1]!, tenantId: m[2]!, subjectId: m[3]! }
}

async function audit(
  deps: { auditLog?: AuditLog },
  event: Parameters<AuditLog["log"]>[0],
): Promise<void> {
  if (!deps.auditLog) return
  try {
    await deps.auditLog.log(event)
  } catch {
    /* swallow */
  }
}
