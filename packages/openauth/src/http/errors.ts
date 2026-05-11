/**
 * Map an `AuthError` into a standards-compliant HTTP response.
 *
 * Two surfaces:
 *   - **Token / introspect / revoke endpoints (RFC 6749 §5.2).** JSON body
 *     `{ "error": "...", "error_description": "..." }` with the spec status
 *     codes (`invalid_client` → 401, server-side → 500, the rest → 400).
 *   - **Authorize endpoint (RFC 6749 §4.1.2.1).** Recoverable errors redirect
 *     back to the relying party with `error` + `error_description` + the
 *     echoed `state`. Non-recoverable errors (unknown client, unregistered
 *     redirect_uri) surface as plain text to avoid open-redirector behavior.
 *
 * `internal_error` is framework-internal; the HTTP layer always rewrites it
 * to `server_error` before responding to the client.
 */
import type { AuthError, AuthErrorCode } from "../types/error"

const TOKEN_STATUS: Partial<Record<AuthErrorCode, number>> = {
  invalid_client: 401,
  server_error: 500,
  internal_error: 500,
  tenant_not_found: 400,
}

/** Public OAuth error code emitted on the wire. Strips framework-internal. */
export function publicErrorCode(code: AuthErrorCode): string {
  if (code === "internal_error") return "server_error"
  if (code === "tenant_not_found") return "invalid_request"
  if (code === "method_not_found") return "invalid_request"
  if (code === "unknown_state") return "invalid_request"
  return code
}

export function tokenEndpointErrorResponse(error: AuthError): Response {
  const status = TOKEN_STATUS[error.code] ?? 400
  const body = {
    error: publicErrorCode(error.code),
    error_description: error.description,
  }
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": "no-store",
    pragma: "no-cache",
  })
  if (status === 401) {
    headers.set("www-authenticate", `Basic realm="oauth"`)
  }
  return new Response(JSON.stringify(body), { status, headers })
}

/**
 * Redirect back to the RP with the OAuth error in the query (RFC 6749
 * §4.1.2.1). Returns `null` if the error is non-recoverable — the caller
 * should render a plain-text response instead.
 */
export function authorizeRedirectErrorResponse(
  error: AuthError,
  appRedirectUri: string,
  appState: string | null,
): Response {
  const url = new URL(appRedirectUri)
  url.searchParams.set("error", publicErrorCode(error.code))
  url.searchParams.set("error_description", error.description)
  if (appState !== null) url.searchParams.set("state", appState)
  return new Response(null, {
    status: 302,
    headers: { location: url.toString(), "cache-control": "no-store" },
  })
}

/**
 * Plain-text fallback for errors that occur before a valid `redirect_uri`
 * has been established — open-redirector defense.
 */
export function authorizeDirectErrorResponse(error: AuthError): Response {
  const body = `${publicErrorCode(error.code)}: ${error.description}`
  return new Response(body, {
    status: 400,
    headers: { "content-type": "text/plain", "cache-control": "no-store" },
  })
}

/**
 * Errors that must never round-trip through `appRedirectUri` because the URI
 * itself is what failed validation.
 */
export function isNonRecoverable(error: AuthError): boolean {
  if (error.code === "invalid_client") return true
  if (error.code === "tenant_not_found") return true
  if (error.code === "method_not_found") return true
  if (
    error.code === "invalid_request" &&
    (error as { field?: string }).field === "redirect_uri"
  ) {
    return true
  }
  return false
}
