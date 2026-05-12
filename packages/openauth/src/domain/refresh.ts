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

import { verifyClientCredentials } from "./client-auth"
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
  // Peek before consuming so we can authenticate the client without
  // burning the token on auth failures (RFC 6749 §6).
  const peek = await deps.tokenStore.peekRefresh(req.refreshToken)
  if (isErr(peek)) return err(peek.error)
  const peekedPayload = peek.value

  const tenantCfg = await deps.configStore.getTenantConfig(peekedPayload.tenantId)
  if (isErr(tenantCfg)) return err(tenantCfg.error)

  // Authenticate the *presenting* client first, then check ownership.
  // Wrong-secret, wrong-client, and unknown-presenting-client all collapse
  // to the same `invalid_grant` response so an attacker holding a stolen
  // refresh token cannot probe candidate `client_id` values: every
  // misroute looks identical on the wire (RFC 6749 §5.2; H4 of the
  // post-rebuild review).
  const INVALID_REFRESH_DESC = "refresh token is invalid"
  const client = tenantCfg.value.clients.find(
    (c) => c.id === peekedPayload.clientId,
  )
  if (!client) {
    return err(authError.invalidGrant(INVALID_REFRESH_DESC))
  }

  if (req.clientId !== undefined) {
    const presenting = tenantCfg.value.clients.find(
      (c) => c.id === req.clientId,
    )
    if (!presenting) {
      return err(authError.invalidGrant(INVALID_REFRESH_DESC))
    }
    const authErr = await verifyClientCredentials(presenting, req.clientSecret)
    if (authErr) return err(authError.invalidGrant(INVALID_REFRESH_DESC))
    if (req.clientId !== peekedPayload.clientId) {
      return err(authError.invalidGrant(INVALID_REFRESH_DESC))
    }
  } else if (client.type === "confidential") {
    return err(authError.invalidGrant(INVALID_REFRESH_DESC))
  }

  const consumed = await deps.tokenStore.consumeRefresh(req.refreshToken, {
    reuseWindowMs: deps.reuseWindowMs,
  })
  if (isErr(consumed)) {
    if (consumed.error.description.includes("reuse detected")) {
      // tenantId / subjectId come from the peeked payload (branded
      // TenantId, FK-safe). Only `family` is read from the adapter's
      // description string — if the adapter doesn't follow the
      // convention, we fall back to the payload's family.
      const parsed = parseReuseSignal(consumed.error.description)
      await audit(deps, {
        kind: "refresh_reuse_detected",
        tenantId: peekedPayload.tenantId,
        clientId: peekedPayload.clientId,
        family: parsed.family !== "unknown" ? parsed.family : peekedPayload.family,
        timestamp: deps.clock(),
      })
    }
    return err(consumed.error)
  }
  const payload = consumed.value

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
 * `... (family=<id>,tenant=<id>,subject=<id>)`. We only consume `family`
 * here — `tenantId` / `subjectId` come from the peeked payload (which is
 * already properly branded). Adapters that don't follow the convention
 * still emit a useful audit event (we fall back to the payload's
 * `family`); this parser will be replaced with a typed `reuseSignal`
 * field on `AuthError` under H10.
 */
function parseReuseSignal(description: string): { family: string } {
  const m = description.match(/family=([^,)]+)/)
  if (!m) return { family: "unknown" }
  return { family: m[1]! }
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
