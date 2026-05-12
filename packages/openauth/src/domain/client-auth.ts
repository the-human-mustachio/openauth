/**
 * Shared client-authentication helpers.
 *
 * `/token`, `/revoke`, `/introspect`, and refresh-token rotation all need
 * to validate presented credentials against a `ClientConfig`. The logic is
 * the same in every case:
 *
 *  - **Public clients** MUST NOT present a `client_secret` (RFC 6749 §2.3).
 *  - **Confidential clients** MUST present a `client_secret`, hashed and
 *    compared in constant time against `ClientConfig.secretHash`.
 *
 * Credentials may ride either in the form body (`client_id`,
 * `client_secret`) or in an `Authorization: Basic` header
 * (RFC 6749 §2.3.1). Both encodings are accepted; the header takes
 * precedence when both are present.
 *
 * The hashing function lives in `./token.ts` (`hashClientSecret`) to keep
 * the legacy phase-2 SHA-256 / base64url format in one place; production
 * deployments migrate to argon2id later in the rebuild.
 */
import { authError, type AuthError } from "../types/error"
import type { ClientConfig } from "../types/tenant"

import { timingSafeEqualStr } from "./crypto"
import { hashClientSecret } from "./token"

export type ClientCredentials = {
  /** Client identifier (always present when credentials are presented). */
  clientId: string
  /** Confidential clients only. */
  clientSecret?: string
}

/**
 * Validate presented credentials against `client`. Returns `null` on
 * success, `AuthError` on rejection.
 *
 * Public clients pass when no secret is presented. Confidential clients
 * require both a secret and a matching `secretHash`.
 */
export async function verifyClientCredentials(
  client: ClientConfig,
  presentedSecret: string | undefined,
): Promise<AuthError | null> {
  if (client.type === "public") {
    if (presentedSecret) {
      return authError.invalidClient(
        "public clients must not present a client_secret",
      )
    }
    return null
  }
  if (!presentedSecret) {
    return authError.invalidClient("confidential client requires client_secret")
  }
  const supplied = await hashClientSecret(presentedSecret)
  if (!timingSafeEqualStr(supplied, client.secretHash)) {
    return authError.invalidClient("client_secret mismatch")
  }
  return null
}

/**
 * Parse an `Authorization: Basic <base64>` header.
 *
 * Returns `null` for missing / non-Basic headers and for any decoding
 * failure; callers fall back to form-body credentials.
 */
export function parseBasicAuth(
  header: string | null,
): ClientCredentials | null {
  if (!header) return null
  const match = /^Basic\s+(.+)$/i.exec(header)
  if (!match || !match[1]) return null
  let decoded: string
  try {
    decoded = atob(match[1])
  } catch {
    return null
  }
  const colon = decoded.indexOf(":")
  if (colon === -1) return null
  let clientId: string
  let clientSecret: string
  try {
    clientId = decodeURIComponent(decoded.slice(0, colon))
    clientSecret = decodeURIComponent(decoded.slice(colon + 1))
  } catch {
    return null
  }
  return { clientId, clientSecret }
}

/**
 * Merge form-body credentials with an optional `Authorization: Basic`
 * header. The header wins per RFC 6749 §2.3 when both are present.
 *
 * Returns `null` when neither source supplies a `client_id` — callers
 * then decide whether that's permissible (anonymous revoke is OK; the
 * token endpoint isn't).
 */
export function resolveClientCredentials(input: {
  authorizationHeader: string | null
  bodyClientId: string | undefined
  bodyClientSecret: string | undefined
}): ClientCredentials | null {
  const basic = parseBasicAuth(input.authorizationHeader)
  if (basic) return basic
  if (!input.bodyClientId) return null
  return {
    clientId: input.bodyClientId,
    ...(input.bodyClientSecret !== undefined
      ? { clientSecret: input.bodyClientSecret }
      : {}),
  }
}
