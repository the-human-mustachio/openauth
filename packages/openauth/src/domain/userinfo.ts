/**
 * `/userinfo` endpoint logic (OIDC Core §5.3). Verifies the presented
 * access token, optionally enforces a DPoP proof binding (RFC 9449 §7),
 * and returns the inlined `SubjectClaim` claims, scope-gated per OIDC
 * Core §5.4.
 *
 * Profile / email / phone / address claims appear in the response only
 * when (a) the access token's `scope` includes the granting scope and
 * (b) the value exists on `SubjectClaim.properties`. Other properties
 * (host-specific subject fields like `userId`, `roles`, …) are returned
 * under `properties` and not subject to OIDC scope gating — they're
 * outside §5.4's universe.
 *
 * DPoP at the resource server (RFC 9449 §7):
 *  - If the access token has a `cnf.jkt` claim, the request MUST carry a
 *    matching `DPoP:` proof whose `ath` equals SHA-256(access_token).
 *  - If no `cnf.jkt`, the access token is plain Bearer and any DPoP
 *    proof is silently ignored at this layer (host can still enforce).
 */
import type { TokenStore } from "../ports/token-store"
import type { KeyStore } from "../ports/key-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { SubjectClaim } from "../types/subject"
import type { AccessTokenClaims } from "../types/token"

import { computeAth, verifyDpopProof } from "./dpop"
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
  /** Required when DPoP-bound tokens are accepted. */
  tokenStore?: TokenStore
  issuerUrl?: string
}

export type UserinfoInput = {
  /** Access token from `Authorization: Bearer ...` or `Authorization: DPoP ...`. */
  accessToken: string
  /** `Authorization`-scheme as presented. Defaults to `"Bearer"`. */
  scheme?: "Bearer" | "DPoP"
  /** Raw `DPoP:` header from the request, if any. */
  dpopProof?: string
  /** Canonical request URI for DPoP `htu` check (scheme + host + path). */
  htu?: string
  /** Request method for DPoP `htm` check, uppercase. */
  htm?: string
  /** Wall clock seconds for DPoP `iat` window. */
  nowSec?: number
}

export async function userinfo(
  input: UserinfoInput,
  deps: UserinfoDeps,
): Promise<Result<UserinfoResponse, AuthError>> {
  const keysRes = await deps.keyStore.signingKeys()
  if (isErr(keysRes)) return err(keysRes.error)

  let claims: AccessTokenClaims
  try {
    claims = await verifyAccessToken(input.accessToken, keysRes.value, {
      ...(deps.issuerUrl ? { issuer: deps.issuerUrl } : {}),
    })
  } catch {
    return err(authError.invalidGrant("access token invalid or expired"))
  }

  // RFC 9449 §7 — DPoP-bound tokens require a matching proof at the RS.
  const boundJkt = claims.cnf?.jkt
  if (boundJkt !== undefined) {
    if (input.scheme !== "DPoP") {
      return err(
        authError.invalidDpopProof(
          'access token is DPoP-bound; Authorization scheme must be "DPoP"',
        ),
      )
    }
    if (!input.dpopProof) {
      return err(
        authError.invalidDpopProof(
          "access token is DPoP-bound; request is missing a DPoP proof",
        ),
      )
    }
    if (!input.htu || !input.htm || input.nowSec === undefined) {
      return err(
        authError.invalidDpopProof(
          "userinfo dpop verification requires htu, htm, and nowSec",
        ),
      )
    }
    if (!deps.tokenStore) {
      return err(
        authError.invalidDpopProof(
          "userinfo dpop verification requires a token-store (jti replay protection)",
        ),
      )
    }
    const expectedAth = await computeAth(input.accessToken)
    const dpopRes = await verifyDpopProof(
      {
        proofJwt: input.dpopProof,
        htu: input.htu,
        htm: input.htm,
        nowSec: input.nowSec,
        expectedAth,
      },
      { tokenStore: deps.tokenStore },
    )
    if (isErr(dpopRes)) return err(dpopRes.error)
    if (dpopRes.value.jkt !== boundJkt) {
      return err(
        authError.invalidDpopProof(
          "dpop proof key does not match access token cnf.jkt",
        ),
      )
    }
  } else if (input.scheme === "DPoP") {
    // Token isn't bound but caller used the DPoP scheme — reject so a
    // confused-deputy can't accidentally rely on RS-side enforcement.
    return err(
      authError.invalidGrant(
        'access token is not DPoP-bound; use Authorization: Bearer',
      ),
    )
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
