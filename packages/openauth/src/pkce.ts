/**
 * Client-side PKCE generator — used by `@_mustachio/openauth/client` to
 * produce a verifier + S256 challenge pair before redirecting the user to
 * `/authorize`.
 *
 * S256-only. Per OAuth 2.1 the `plain` method is prohibited; this module
 * does not expose a verifier-comparison helper because IdP-side validation
 * lives in `domain/pkce.ts` and runs against the stored challenge from the
 * auth-code payload — no consumer of this file has a legitimate reason to
 * recompute a challenge.
 */
import { base64url } from "jose"

function generateVerifier(length: number): string {
  const buffer = new Uint8Array(length)
  crypto.getRandomValues(buffer)
  return base64url.encode(buffer)
}

async function s256Challenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const hash = await crypto.subtle.digest("SHA-256", data)
  return base64url.encode(new Uint8Array(hash))
}

export async function generatePKCE(length: number = 64): Promise<{
  verifier: string
  challenge: string
  method: "S256"
}> {
  if (length < 43 || length > 128) {
    throw new Error(
      "Code verifier length must be between 43 and 128 characters",
    )
  }
  const verifier = generateVerifier(length)
  const challenge = await s256Challenge(verifier)
  return { verifier, challenge, method: "S256" }
}
