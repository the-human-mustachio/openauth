/**
 * `/revoke` endpoint logic (RFC 7009). HTTP shim lands in Phase 8; the
 * domain function is already needed so refresh-token rotation reuse
 * detection can revoke a chain.
 *
 * Revoking an access token is a no-op for this IdP (access tokens are
 * stateless JWTs — revocation has to wait for natural expiry). Revoking
 * a refresh token consumes it; if the caller supplied a hint that this
 * is the full subject, all refresh tokens for that subject are revoked.
 */
import type { AuditLog } from "../ports/audit-log"
import type { TokenStore } from "../ports/token-store"
import type { AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantId } from "../types/tenant"

export type RevokeRequest = {
  token: string
  /** RFC 7009 hint: `"access_token"` or `"refresh_token"`. */
  tokenTypeHint?: "access_token" | "refresh_token"
}

export type RevokeDeps = {
  tokenStore: TokenStore
  auditLog?: AuditLog
  clock: () => number
}

/**
 * Revoke a single refresh token. Access tokens are not server-side state
 * in this IdP, so an `access_token` hint resolves to a no-op (per RFC 7009
 * §2.2 a revoke for an already-invalid token returns 200).
 */
export async function revokeToken(
  req: RevokeRequest,
  deps: RevokeDeps,
): Promise<Result<void, AuthError>> {
  if (req.tokenTypeHint === "access_token") {
    return ok(undefined)
  }
  // Treat anything else as a refresh token. Try consume; if not found,
  // RFC 7009 says treat as success.
  const res = await deps.tokenStore.consumeRefresh(req.token, {
    reuseWindowMs: 0,
  })
  if (isErr(res)) {
    // Already revoked / unknown — RFC 7009 §2.2 successful no-op.
    return ok(undefined)
  }
  const payload = res.value
  await audit(deps, {
    kind: "token_revoked",
    tenantId: payload.tenantId,
    clientId: payload.clientId,
    subjectId: payload.subjectId,
    family: payload.family,
    reason: "client_revoke",
    timestamp: deps.clock(),
  })
  return ok(undefined)
}

/** Revoke every refresh token for a subject — used by reuse-detection escalation. */
export async function revokeAllForSubject(
  tenantId: TenantId,
  subjectId: string,
  deps: RevokeDeps,
): Promise<Result<void, AuthError>> {
  const res = await deps.tokenStore.revokeBySubject(tenantId, subjectId)
  if (isErr(res)) return err(res.error)
  await audit(deps, {
    kind: "token_revoked",
    tenantId,
    clientId: null,
    subjectId,
    reason: "subject_revoke",
    timestamp: deps.clock(),
  })
  return ok(undefined)
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
