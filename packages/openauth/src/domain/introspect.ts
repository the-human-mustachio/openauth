/**
 * `/introspect` endpoint logic (RFC 7662). HTTP shim lands in Phase 8.
 *
 * For access tokens (JWT): verify signature + expiry against the
 * `KeyStore` JWKS, return active/inactive + standard claims.
 *
 * For refresh tokens (opaque): not introspected here — refresh-token
 * lookup is a privileged operation that bypasses introspection per
 * convention (RFC 7662 §2.1 only requires access-token introspection).
 */
import type { KeyStore } from "../ports/key-store"
import type { AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { AccessTokenClaims } from "../types/token"

import { verifyAccessToken } from "./jwt"

export type IntrospectResponse =
  | { active: false }
  | {
      active: true
      sub: string
      aud: string
      iss: string
      exp: number
      iat: number
      scope?: string
      client_id?: string
      tid: string
      mid?: string
      mkind?: string
    }

export type IntrospectDeps = {
  keyStore: KeyStore
  /** Expected issuer for additional validation. */
  issuerUrl?: string
}

export async function introspect(
  token: string,
  deps: IntrospectDeps,
): Promise<Result<IntrospectResponse, AuthError>> {
  const keysRes = await deps.keyStore.signingKeys()
  if (isErr(keysRes)) return err(keysRes.error)

  let claims: AccessTokenClaims
  try {
    claims = await verifyAccessToken(token, keysRes.value, {
      ...(deps.issuerUrl ? { issuer: deps.issuerUrl } : {}),
    })
  } catch {
    return ok({ active: false })
  }

  return ok({
    active: true,
    sub: claims.sub,
    aud: claims.aud,
    iss: claims.iss,
    exp: claims.exp,
    iat: claims.iat,
    scope: claims.scope,
    client_id: claims.aud,
    tid: claims.tid,
    mid: claims.mid,
    mkind: claims.mkind,
  })
}
