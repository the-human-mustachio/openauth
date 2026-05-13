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

import type { AccessTokenClaims, IdTokenClaims } from "../types/token"
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
 * Sign an OIDC `id_token` claim set (OIDC Core §2). Header `typ` is
 * `"JWT"` per common practice; OIDC Core does not mandate `"id_token"`.
 * The claims object is verified by the caller to include `iss`, `sub`,
 * `aud`, `exp`, `iat` (REQUIRED per §2).
 */
export async function signIdToken(
  claims: IdTokenClaims,
  privateKey: KeyLike,
  alg: string,
  kid: string,
): Promise<string> {
  return new SignJWT(claims as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg, typ: "JWT", kid })
    .sign(privateKey)
}

/**
 * Verify an OIDC `id_token` against the IdP's published signing keys.
 * Used at `/end_session` to validate `id_token_hint` and by adjacent
 * domain code that needs to introspect a previously-issued id_token.
 *
 * Same algorithm-confusion defenses as `verifyAccessToken`: only the
 * asymmetric allow-list (`ES256`, `EdDSA`) accepted; `alg: "none"`
 * rejected explicitly.
 */
export async function verifyIdToken(
  token: string,
  keys: ReadonlyArray<SigningKey>,
  options: { issuer?: string; audience?: string } = {},
): Promise<IdTokenClaims> {
  const algorithms = Array.from(
    new Set(keys.map((k) => k.alg).filter((a) => ASYMMETRIC_ALGS.has(a))),
  )
  const { payload } = await jwtVerify<IdTokenClaims>(
    token,
    async (header) => {
      if (!header.alg || header.alg === "none") {
        throw new Error(`verifyIdToken: refusing alg "${header.alg ?? ""}"`)
      }
      const match = keys.find((k) => k.kid === header.kid)
      if (!match) {
        throw new Error(`verifyIdToken: unknown kid "${header.kid}"`)
      }
      if (match.alg !== header.alg) {
        throw new Error(
          `verifyIdToken: header.alg "${header.alg}" does not match key alg "${match.alg}"`,
        )
      }
      const imported = await importJWK(
        match.publicJwk as unknown as JWK,
        match.alg,
      )
      return imported as KeyLike
    },
    {
      algorithms,
      ...(options.issuer ? { issuer: options.issuer } : {}),
      ...(options.audience ? { audience: options.audience } : {}),
    },
  )
  return payload
}

/** Allow-list of asymmetric `alg` values the IdP issues + accepts. */
const ASYMMETRIC_ALGS: ReadonlySet<string> = new Set(["ES256", "EdDSA"])

/**
 * Verify a JWT access token using a list of trusted signing keys (from
 * `KeyStore.signingKeys()`). Looks up by `kid` in the JWT header.
 *
 * Algorithm enforcement: the allow-list is derived from the loaded
 * `SigningKey.alg` values, intersected with the asymmetric allow-list
 * (`ES256`, `EdDSA`). Symmetric (`HS*`) and `none` are filtered out, so a
 * symmetric key accidentally landing in the store does not open an
 * alg-confusion path. The kid resolver also rejects `alg: "none"`
 * explicitly as defense in depth — `jose` already refuses tokens whose
 * header `alg` is outside `algorithms`, but a future call site that
 * dropped the option would still be safe.
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
  const algorithms = Array.from(
    new Set(keys.map((k) => k.alg).filter((a) => ASYMMETRIC_ALGS.has(a))),
  )
  const { payload } = await jwtVerify<AccessTokenClaims>(
    token,
    async (header) => {
      if (!header.alg || header.alg === "none") {
        throw new Error(`verifyAccessToken: refusing alg "${header.alg ?? ""}"`)
      }
      const match = keys.find((k) => k.kid === header.kid)
      if (!match) {
        throw new Error(`verifyAccessToken: unknown kid "${header.kid}"`)
      }
      if (match.alg !== header.alg) {
        throw new Error(
          `verifyAccessToken: header.alg "${header.alg}" does not match key alg "${match.alg}"`,
        )
      }
      const imported = await importJWK(
        match.publicJwk as unknown as JWK,
        match.alg,
      )
      return imported as KeyLike
    },
    {
      algorithms,
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
