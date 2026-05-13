/**
 * DPoP — Demonstration of Proof-of-Possession (RFC 9449).
 *
 * The RP/client generates an asymmetric key pair, sends a fresh proof
 * JWT with each authenticated request, and the IdP binds the issued
 * access token to the public key's SHA-256 thumbprint (`cnf.jkt`).
 *
 * This module parses + verifies DPoP proof JWTs. Replay protection is
 * delegated to `TokenStore.recordDpopJti`; adapters without that method
 * cannot satisfy DPoP and the verifier returns `invalid_dpop_proof`.
 *
 * Per RFC 9449 §4.2/§4.3, the proof JWT carries:
 *   - header: `typ: "dpop+jwt"`, `alg: <asymmetric>`, `jwk: <pub-JWK>`
 *   - payload: `htu`, `htm`, `iat`, `jti`, optional `ath`, optional `nonce`
 *
 * Verification chain (§4.3):
 *   1. Header `typ` is exactly `"dpop+jwt"`.
 *   2. `alg` is in the asymmetric allow-list (`ES256`, `EdDSA`).
 *   3. `jwk` is a public key in JWK form; signature verifies under it.
 *   4. `htm` equals the request method (case-sensitive).
 *   5. `htu` equals the request URI (scheme + host + path; query / frag stripped).
 *   6. `iat` is within ±`iatToleranceSec` of `now`.
 *   7. `jti` has not been seen within the replay window (TokenStore-tracked).
 *   8. If `expectedAth` supplied (resource-server check), `ath` matches.
 *
 * The thumbprint (`jkt`) is computed via RFC 7638 over the public JWK.
 */
import type { JWK, KeyLike } from "jose"
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify } from "jose"

import type { TokenStore } from "../ports/token-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"

import { base64url, sha256, utf8 } from "./crypto"

/** Allow-list of `alg` values accepted in DPoP proofs. Asymmetric only. */
const DPOP_ASYMMETRIC_ALGS: ReadonlySet<string> = new Set(["ES256", "EdDSA"])

/** RFC 9449 §4.2 — fixed 60-second tolerance is the conventional default. */
export const DEFAULT_DPOP_IAT_TOLERANCE_SEC = 60

/** Replay-window TTL for `jti` tracking. Matches `iat` tolerance × 2. */
export const DEFAULT_DPOP_JTI_TTL_MS = 2 * DEFAULT_DPOP_IAT_TOLERANCE_SEC * 1000

export type DpopProofPayload = {
  htu: string
  htm: string
  iat: number
  jti: string
  ath?: string
  nonce?: string
}

export type VerifiedDpopProof = {
  /** RFC 7638 JWK thumbprint of the proof's public key. */
  jkt: string
  /** The decoded + signature-verified proof payload. */
  payload: DpopProofPayload
}

export type VerifyDpopProofInput = {
  proofJwt: string
  /** Actual request URI (scheme + host + port + path; query/frag stripped). */
  htu: string
  /** Actual HTTP method, uppercase. */
  htm: string
  /** Wall clock seconds. */
  nowSec: number
  /** Optional skew allowance. */
  iatToleranceSec?: number
  /**
   * Required at resource servers when the proof must bind to a presented
   * access token. The verifier checks the proof's `ath` equals
   * base64url(SHA-256(access_token ASCII)). Omit at the AS `/token`
   * endpoint — no access token exists yet there.
   */
  expectedAth?: string
}

export type VerifyDpopProofDeps = {
  tokenStore: TokenStore
  jtiTtlMs?: number
}

/**
 * Verify a DPoP proof JWT and return its `jkt` + payload. Side-effect:
 * records the `jti` in `TokenStore` so a replay within the TTL window
 * is rejected.
 */
export async function verifyDpopProof(
  input: VerifyDpopProofInput,
  deps: VerifyDpopProofDeps,
): Promise<Result<VerifiedDpopProof, AuthError>> {
  if (!deps.tokenStore.recordDpopJti) {
    return err(
      authError.invalidDpopProof(
        "token-store adapter does not support DPoP replay protection",
      ),
    )
  }
  // 1. Decode the header to recover the embedded JWK + check `typ`/`alg`
  //    before the signature verification call so we can return precise
  //    errors instead of a generic jose failure.
  let header: ReturnType<typeof decodeProtectedHeader>
  try {
    header = decodeProtectedHeader(input.proofJwt)
  } catch (e) {
    return err(
      authError.invalidDpopProof(
        `dpop proof header is not a valid compact JWS: ${stringifyError(e)}`,
      ),
    )
  }
  if (header.typ !== "dpop+jwt") {
    return err(
      authError.invalidDpopProof(
        `dpop proof header.typ must be "dpop+jwt", got "${String(header.typ)}"`,
      ),
    )
  }
  if (!header.alg || !DPOP_ASYMMETRIC_ALGS.has(header.alg)) {
    return err(
      authError.invalidDpopProof(
        `dpop proof alg "${String(header.alg)}" not in {ES256, EdDSA}`,
      ),
    )
  }
  const jwk = header.jwk as JWK | undefined
  if (!jwk || typeof jwk !== "object") {
    return err(
      authError.invalidDpopProof(
        "dpop proof header.jwk missing or not an object",
      ),
    )
  }
  // §4.2: the embedded JWK MUST be a public key. Reject anything that
  // looks like a private key (`d` for EC / OKP, `d`+`p`+`q` for RSA).
  if ("d" in jwk) {
    return err(
      authError.invalidDpopProof(
        "dpop proof header.jwk must be a public key (private material present)",
      ),
    )
  }

  // 2. Verify the signature with the embedded JWK.
  let key: KeyLike
  try {
    key = (await importJWK(jwk, header.alg)) as KeyLike
  } catch (e) {
    return err(
      authError.invalidDpopProof(
        `dpop proof JWK import failed: ${stringifyError(e)}`,
      ),
    )
  }
  let verified
  try {
    verified = await jwtVerify(input.proofJwt, key, {
      algorithms: [header.alg],
    })
  } catch (e) {
    return err(
      authError.invalidDpopProof(
        `dpop proof signature verification failed: ${stringifyError(e)}`,
      ),
    )
  }
  const payload = verified.payload as Partial<DpopProofPayload>

  // 3. Payload-shape checks. The compact set: htu, htm, iat, jti.
  if (typeof payload.htm !== "string") {
    return err(authError.invalidDpopProof("dpop proof missing string htm"))
  }
  if (typeof payload.htu !== "string") {
    return err(authError.invalidDpopProof("dpop proof missing string htu"))
  }
  if (typeof payload.iat !== "number") {
    return err(authError.invalidDpopProof("dpop proof missing numeric iat"))
  }
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    return err(
      authError.invalidDpopProof("dpop proof missing non-empty string jti"),
    )
  }

  // 4. htm / htu equality.
  if (payload.htm !== input.htm) {
    return err(
      authError.invalidDpopProof(
        `dpop htm "${payload.htm}" does not match request method "${input.htm}"`,
      ),
    )
  }
  if (payload.htu !== input.htu) {
    return err(
      authError.invalidDpopProof(
        `dpop htu "${payload.htu}" does not match request uri "${input.htu}"`,
      ),
    )
  }

  // 5. iat freshness.
  const tolerance = input.iatToleranceSec ?? DEFAULT_DPOP_IAT_TOLERANCE_SEC
  const skew = Math.abs(input.nowSec - payload.iat)
  if (skew > tolerance) {
    return err(
      authError.invalidDpopProof(
        `dpop iat skew ${skew}s exceeds tolerance ${tolerance}s`,
      ),
    )
  }

  // 6. ath check (RS use only).
  if (input.expectedAth !== undefined) {
    if (typeof payload.ath !== "string" || payload.ath !== input.expectedAth) {
      return err(
        authError.invalidDpopProof(
          "dpop ath does not match SHA-256 of the access token",
        ),
      )
    }
  }

  // 7. jti replay protection — atomic record-or-fail in the token store.
  const recorded = await deps.tokenStore.recordDpopJti(
    payload.jti,
    deps.jtiTtlMs ?? DEFAULT_DPOP_JTI_TTL_MS,
  )
  if (isErr(recorded)) {
    return err(
      authError.invalidDpopProof(`dpop jti "${payload.jti}" replayed`),
    )
  }

  // 8. Compute jkt thumbprint (RFC 7638) — bound onto the issued token.
  let jkt: string
  try {
    jkt = await calculateJwkThumbprint(jwk, "sha256")
  } catch (e) {
    return err(
      authError.invalidDpopProof(
        `dpop jkt thumbprint computation failed: ${stringifyError(e)}`,
      ),
    )
  }

  return ok({
    jkt,
    payload: {
      htm: payload.htm,
      htu: payload.htu,
      iat: payload.iat,
      jti: payload.jti,
      ...(payload.ath !== undefined ? { ath: payload.ath } : {}),
      ...(payload.nonce !== undefined ? { nonce: payload.nonce } : {}),
    },
  })
}

/**
 * Canonicalize a request URL for `htu` comparison (RFC 9449 §4.3).
 * Strips query string and fragment; preserves scheme, host, port, path.
 * Default port for the scheme is removed.
 */
export function canonicalHtu(rawUrl: string): string {
  const u = new URL(rawUrl)
  u.search = ""
  u.hash = ""
  // Normalize default ports per the URL spec — `new URL("https://x:443").port` is "".
  return u.toString()
}

/**
 * Compute the `ath` value (RFC 9449 §4.2): base64url(SHA-256(access_token ASCII)).
 * Resource servers compare the presented DPoP proof's `ath` to this.
 */
export async function computeAth(accessToken: string): Promise<string> {
  return base64url.encode(await sha256(utf8.encode(accessToken)))
}

function stringifyError(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
