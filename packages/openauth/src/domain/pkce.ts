/**
 * PKCE validation. OAuth 2.1 mandates the `S256` method; `plain` is **not**
 * supported by this IdP.
 */
import { base64url, sha256, timingSafeEqualStr, utf8 } from "./crypto"

/**
 * Compute the S256 challenge for a verifier. Used at `/token` to recompute
 * the expected challenge from the supplied `code_verifier` and compare it
 * (timing-safe) against the challenge stashed in the auth-code payload.
 */
export async function s256Challenge(verifier: string): Promise<string> {
  return base64url.encode(await sha256(utf8.encode(verifier)))
}

/**
 * Verify a `code_verifier` against a previously-stored `code_challenge`.
 *
 * - Returns `false` on any length / character anomaly without computing the
 *   hash — these are public-shape checks, not secret-dependent.
 * - Uses a constant-time compare for the recomputed challenge.
 */
export async function validatePkce(
  verifier: string,
  challenge: string,
): Promise<boolean> {
  if (
    typeof verifier !== "string" ||
    typeof challenge !== "string" ||
    verifier.length < 43 ||
    verifier.length > 128
  ) {
    return false
  }
  const computed = await s256Challenge(verifier)
  return timingSafeEqualStr(computed, challenge)
}
