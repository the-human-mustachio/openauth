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
import type { OnTokenIssued } from "../types/idp"
import type { Result } from "../types/result"
import { err, isErr } from "../types/result"
import type { TenantContext } from "../types/tenant"
import type { TokenResponse } from "../types/token"

import { safeAudit } from "./audit"
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
  /**
   * RFC 9449 §6 — JWK thumbprint of the DPoP proof presented on this
   * refresh request. MUST match `RefreshTokenPayload.dpopJkt` when the
   * original grant was DPoP-bound; presence is REQUIRED for bound
   * tokens, OPTIONAL otherwise.
   */
  dpopJkt?: string
}

export type RefreshTokensDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  auditLog?: AuditLog
  issuerUrl: string
  clock: () => number
  /** See `IdPOptions.onTokenIssued`. Threaded to `mintTokens`. */
  onTokenIssued?: OnTokenIssued
  /** Reuse-detection window (ms). Default 60 s. */
  reuseWindowMs?: number
  newRefreshToken?: () => string
  /** See `IdPOptions.customScopeClaims`. Forwarded to `mintTokens`. */
  customScopeClaims?: Record<string, ReadonlyArray<string>>
}

/**
 * Requested scopes must be a subset of what the grant carries (RFC 6749
 * §6). Returns the error rather than throwing so both call sites -- the
 * pre-consume gate and the post-consume re-check -- read identically.
 */
function validateRequestedScopes(
  requested: string | undefined,
  granted: string[],
): AuthError | null {
  if (!requested) return null
  for (const s of requested.split(" ").filter(Boolean)) {
    if (!granted.includes(s)) {
      return authError.invalidScope(
        `requested scope "${s}" not granted by original refresh token`,
      )
    }
  }
  return null
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

  const tenantCfg = await deps.configStore.getTenantConfig(
    peekedPayload.tenantId,
  )
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

  // RFC 9449 §5 — when the refresh token is DPoP-bound, verify the
  // presented DPoP thumbprint matches BEFORE consuming. Consuming first
  // would burn the token on a wrong-key probe AND trip reuse-detection
  // on a subsequent legitimate retry with the right key.
  if (peekedPayload.dpopJkt !== undefined) {
    if (req.dpopJkt === undefined) {
      return err(
        authError.invalidDpopProof(
          "refresh token is DPoP-bound; request is missing a DPoP proof",
        ),
      )
    }
    if (req.dpopJkt !== peekedPayload.dpopJkt) {
      return err(
        authError.invalidDpopProof(
          "refresh token DPoP jkt does not match the original binding",
        ),
      )
    }
  }

  // Scope narrowing is validated against the *peeked* grant, before the
  // token is consumed. Same reasoning as the client-auth and DPoP gates
  // above: a request the grant cannot satisfy must not burn the token,
  // or a client typo makes the next legitimate refresh look like theft
  // and can revoke the whole family. `consumeRefresh` stays the
  // authoritative atomic gate immediately below (TokenStore port:
  // "callers race peekRefresh then consumeRefresh").
  const scopeErr = validateRequestedScopes(req.scope, peekedPayload.scopes)
  if (scopeErr) return err(scopeErr)

  const consumed = await deps.tokenStore.consumeRefresh(req.refreshToken, {
    reuseWindowMs: deps.reuseWindowMs,
  })
  if (isErr(consumed)) {
    if (consumed.error.code === "invalid_grant" && consumed.error.reuseSignal) {
      // Reuse-detection signal arrives typed on the AuthError. tenantId /
      // subjectId come from the signal when the adapter emits it; we fall
      // back to the peeked payload's fields for adapters that don't
      // (older 4th-party adapters that satisfy the port without the
      // structured carrier). `family` always prefers the signal — it's
      // the discriminating identifier the adapter knows.
      const signal = consumed.error.reuseSignal
      await safeAudit(deps, {
        kind: "refresh_reuse_detected",
        tenantId: peekedPayload.tenantId,
        clientId: peekedPayload.clientId,
        family: signal.family,
        timestamp: deps.clock(),
      })
    }
    return err(consumed.error)
  }
  const payload = consumed.value

  // Re-check against the consumed payload, which the port declares
  // authoritative. In practice this cannot diverge from the peeked
  // grant -- rotation preserves scopes -- so this is defence in depth,
  // not the user-facing gate; that already ran above without burning.
  const authoritativeScopeErr = validateRequestedScopes(
    req.scope,
    payload.scopes,
  )
  if (authoritativeScopeErr) return err(authoritativeScopeErr)
  const requestedScopes = req.scope
    ? req.scope.split(" ").filter(Boolean)
    : payload.scopes

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
      // Carry original method provenance forward — descendant tokens
      // surface the method that started the chain via `mid` / `mkind`,
      // not the grant-type literal "refresh".
      methodId: payload.methodId,
      methodKind: payload.methodKind,
      scopes: requestedScopes,
      audience: payload.audience,
      // `auth_time` is stable across refresh rotations per OIDC Core §12;
      // refresh does not re-authenticate the user. `nonce` is deliberately
      // NOT carried forward — the nonce was bound to the original
      // `/authorize` request and should not reappear on rotated id_tokens.
      authTime: payload.authTime,
      // Preserve DPoP binding across refresh rotation (§6.1).
      ...(payload.dpopJkt !== undefined ? { dpopJkt: payload.dpopJkt } : {}),
      // Preserve OIDC §5.5 claims-parameter intent across refresh (§12).
      ...(payload.claimsRequest !== undefined
        ? { claimsRequest: payload.claimsRequest }
        : {}),
    },
    family: payload.family,
    deps,
  }).then(async (result) => {
    if (result.ok) {
      await safeAudit(deps, {
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
