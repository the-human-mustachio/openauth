/**
 * JWT signing + verification for access tokens, plus the JWKS document
 * builder consumed by `/.well-known/jwks.json`.
 *
 * Per AD9 / AD11, access tokens are JWTs (ES256 default; Ed25519 supported).
 * Refresh tokens are opaque server-side records — they do NOT pass through
 * this module.
 */
import type { JWK, KeyLike } from "jose"
import { importJWK, jwtVerify, SignJWT } from "jose"

import type { AccessTokenClaims } from "../types/token"
import type { SigningKey } from "../ports/key-store"

/**
 * Sign an access-token claim set under the supplied private key. `kid` is
 * stamped into the JWT header so verifiers can look up the right public
 * key from JWKS.
 */
export async function signAccessToken(
  claims: AccessTokenClaims,
  privateKey: KeyLike,
  alg: string,
  kid: string,
): Promise<string> {
  return new SignJWT(claims as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg, typ: "JWT", kid })
    .sign(privateKey)
}

/**
 * Verify a JWT access token using a list of trusted signing keys (from
 * `KeyStore.signingKeys()`). Looks up by `kid` in the JWT header.
 *
 * Returns the typed claims on success. Throws (via `jose`) on any
 * signature, expiry, or alg-mismatch failure — callers wrap in `try` and
 * convert to `Result`.
 */
export async function verifyAccessToken(
  token: string,
  keys: ReadonlyArray<SigningKey>,
  options: { issuer?: string; audience?: string } = {},
): Promise<AccessTokenClaims> {
  const { payload } = await jwtVerify<AccessTokenClaims>(
    token,
    async (header) => {
      const match = keys.find((k) => k.kid === header.kid)
      if (!match) {
        throw new Error(`verifyAccessToken: unknown kid "${header.kid}"`)
      }
      const imported = await importJWK(
        match.publicJwk as unknown as JWK,
        match.alg,
      )
      return imported as KeyLike
    },
    {
      ...(options.issuer ? { issuer: options.issuer } : {}),
      ...(options.audience ? { audience: options.audience } : {}),
    },
  )
  return payload
}

/**
 * Build the JWKS document for `/.well-known/jwks.json`. Includes active +
 * recently-rotated keys (the overlap window) so consumers caching JWKS
 * continue to verify tokens signed under a just-retired key until they
 * refresh.
 */
export function buildJwksDocument(keys: ReadonlyArray<SigningKey>): {
  keys: JWK[]
} {
  return {
    keys: keys.map((k) => ({
      ...k.publicJwk,
      kid: k.kid,
      alg: k.alg,
      use: "sig",
    })) as JWK[],
  }
}
