/**
 * `/userinfo` endpoint logic (OIDC Core §5.3). Verifies the bearer access
 * token and returns the inlined `SubjectClaim` claims.
 */
import type { KeyStore } from "../ports/key-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { SubjectClaim } from "../types/subject"
import type { AccessTokenClaims } from "../types/token"

import { verifyAccessToken } from "./jwt"

export type UserinfoResponse = {
  sub: string
  /** Subject type discriminator (e.g. `"user"` / `"admin"`). */
  subject_type: string
  /** Inlined claim properties. */
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

  return ok({
    sub: claims.sub,
    subject_type: claim.type,
    properties: claim.properties,
    scope: claims.scope,
  })
}
