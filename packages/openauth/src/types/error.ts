/**
 * AuthError — the closed taxonomy returned by every domain function on failure.
 *
 * Codes map 1:1 to OAuth 2.0 / RFC 6749 §5.2 error identifiers, plus a handful
 * of framework-internal codes used before the HTTP layer is reached. The HTTP
 * layer translates `AuthError` into a response (`server_error` is the public
 * mapping for `internal_error` at OAuth endpoints).
 */
export type AuthError =
  | { code: "invalid_request"; description: string; field?: string }
  | { code: "invalid_client"; description: string }
  | { code: "invalid_grant"; description: string }
  | { code: "unauthorized_client"; description: string }
  | { code: "unsupported_grant_type"; description: string }
  | { code: "invalid_scope"; description: string }
  | { code: "access_denied"; description: string }
  | { code: "unknown_state"; description: string }
  // RFC 6749 §5.2 — token endpoint server-side failure (hook threw, downstream
  // unavailable, etc.). Carries an optional `cause` for audit; not returned to
  // the relying party.
  | { code: "server_error"; description: string; cause?: unknown }
  | { code: "tenant_not_found"; description: string; tenantId: string }
  // RFC 8693 §2.2.2 — token-exchange "audience the subject can't reach"
  // signal. Surfaced when the host's `exchangeAudience` hook rejects.
  | { code: "invalid_target"; description: string }
  // Populate whichever was requested (id from MethodConfig.id, or kind from
  // MethodConfig.kind) so operators can find the offending config row.
  | {
      code: "method_not_found"
      description: string
      methodId?: string
      methodKind?: string
    }
  // Framework-internal; the HTTP layer maps this to `server_error` at OAuth
  // endpoints. Use for control-flow signalling that should never escape to a
  // standards-compliant client.
  | { code: "internal_error"; description: string; cause?: unknown }

export type AuthErrorCode = AuthError["code"]

/** Narrow constructor helpers — keep call sites short and types tight. */
export const authError = {
  invalidRequest: (description: string, field?: string): AuthError => ({
    code: "invalid_request",
    description,
    ...(field !== undefined ? { field } : {}),
  }),
  invalidClient: (description: string): AuthError => ({
    code: "invalid_client",
    description,
  }),
  invalidGrant: (description: string): AuthError => ({
    code: "invalid_grant",
    description,
  }),
  unauthorizedClient: (description: string): AuthError => ({
    code: "unauthorized_client",
    description,
  }),
  unsupportedGrantType: (description: string): AuthError => ({
    code: "unsupported_grant_type",
    description,
  }),
  invalidScope: (description: string): AuthError => ({
    code: "invalid_scope",
    description,
  }),
  accessDenied: (description: string): AuthError => ({
    code: "access_denied",
    description,
  }),
  unknownState: (description: string): AuthError => ({
    code: "unknown_state",
    description,
  }),
  serverError: (description: string, cause?: unknown): AuthError => ({
    code: "server_error",
    description,
    ...(cause !== undefined ? { cause } : {}),
  }),
  tenantNotFound: (description: string, tenantId: string): AuthError => ({
    code: "tenant_not_found",
    description,
    tenantId,
  }),
  methodNotFound: (
    description: string,
    refs: { methodId?: string; methodKind?: string },
  ): AuthError => ({
    code: "method_not_found",
    description,
    ...(refs.methodId !== undefined ? { methodId: refs.methodId } : {}),
    ...(refs.methodKind !== undefined ? { methodKind: refs.methodKind } : {}),
  }),
  invalidTarget: (description: string): AuthError => ({
    code: "invalid_target",
    description,
  }),
  internalError: (description: string, cause?: unknown): AuthError => ({
    code: "internal_error",
    description,
    ...(cause !== undefined ? { cause } : {}),
  }),
}
