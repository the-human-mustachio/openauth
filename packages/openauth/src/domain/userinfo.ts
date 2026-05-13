/**
 * `/userinfo` endpoint logic (OIDC Core §5.3). Verifies the bearer access
 * token and returns the inlined `SubjectClaim` claims, scope-gated per
 * OIDC Core §5.4.
 *
 * Profile / email / phone / address claims appear in the response only
 * when (a) the access token's `scope` includes the granting scope and
 * (b) the value exists on `SubjectClaim.properties`. Other properties
 * (host-specific subject fields like `userId`, `roles`, …) are returned
 * under `properties` and not subject to OIDC scope gating — they're
 * outside §5.4's universe.
 */
import type { KeyStore } from "../ports/key-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { SubjectClaim } from "../types/subject"
import type { AccessTokenClaims } from "../types/token"

import { pickScopedClaims } from "./id-token"
import { verifyAccessToken } from "./jwt"
import type { ScopedProfileClaims } from "../types/token"

export type UserinfoResponse = ScopedProfileClaims & {
  sub: string
  /** Subject type discriminator (e.g. `"user"` / `"admin"`). */
  subject_type: string
  /** Inlined claim properties, host-specific and not gated by OIDC scope. */
  properties: Record<string, unknown>
  /** Scope granted to this access token. */
  scope?: string
}

export type UserinfoDeps = {
  keyStore: KeyStore
  issuerUrl?: string
}

export async function userinfo(
  bearerToken: string,
  deps: UserinfoDeps,
): Promise<Result<UserinfoResponse, AuthError>> {
  const keysRes = await deps.keyStore.signingKeys()
  if (isErr(keysRes)) return err(keysRes.error)

  let claims: AccessTokenClaims
  try {
    claims = await verifyAccessToken(bearerToken, keysRes.value, {
      ...(deps.issuerUrl ? { issuer: deps.issuerUrl } : {}),
    })
  } catch {
    return err(authError.invalidGrant("access token invalid or expired"))
  }

  const claim = claims.claim as SubjectClaim & {
    type: string
    properties: Record<string, unknown>
  }

  const scopes = claims.scope ? claims.scope.split(" ").filter(Boolean) : []
  const scopedClaims = pickScopedClaims(claim, scopes)

  return ok({
    sub: claims.sub,
    subject_type: claim.type,
    properties: claim.properties,
    scope: claims.scope,
    ...scopedClaims,
  })
}
