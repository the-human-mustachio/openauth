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
  /**
   * `invalid_grant`. `reuseSignal`, when present, is the structured
   * reuse-detection hint `TokenStore.consumeRefresh` adapters emit on a
   * second-use-within-the-window — used by the refresh-grant handler to
   * audit `refresh_reuse_detected` with branded `TenantId` / `subjectId`
   * fields rather than parsing strings out of `description`.
   */
  | {
      code: "invalid_grant"
      description: string
      reuseSignal?: {
        family: string
        tenantId: string
        subjectId: string
      }
    }
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
  // Uniqueness / state conflict. Raised by hosts from `ScimDirectory`
  // when a create or update collides with an existing record — only the
  // host can know, since only the host stores the rows. The SCIM layer
  // renders it as `409` with `scimType: "uniqueness"`. It has no OAuth
  // endpoint mapping and should never reach one.
  | { code: "conflict"; description: string; attribute?: string }
  // RFC 9449 §5.2 — DPoP proof verification failed (bad signature, htm/htu
  // mismatch, iat outside window, replayed jti, missing/mismatched cnf.jkt).
  // Returned as a 400 with `error="invalid_dpop_proof"` on form-body
  // endpoints; on resource-server endpoints it becomes a 401 with
  // `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
  //
  // `replaySignal`, when present, indicates `recordDpopJti` reported a
  // jti already seen within the replay window. The HTTP layer uses this
  // to emit a `dpop_replay_detected` audit event distinct from other
  // proof failures.
  | {
      code: "invalid_dpop_proof"
      description: string
      replaySignal?: { jti: string }
    }

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
  invalidGrant: (
    description: string,
    reuseSignal?: { family: string; tenantId: string; subjectId: string },
  ): AuthError => ({
    code: "invalid_grant",
    description,
    ...(reuseSignal !== undefined ? { reuseSignal } : {}),
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
  conflict: (description: string, attribute?: string): AuthError => ({
    code: "conflict",
    description,
    ...(attribute !== undefined ? { attribute } : {}),
  }),
  internalError: (description: string, cause?: unknown): AuthError => ({
    code: "internal_error",
    description,
    ...(cause !== undefined ? { cause } : {}),
  }),
  invalidDpopProof: (
    description: string,
    replaySignal?: { jti: string },
  ): AuthError => ({
    code: "invalid_dpop_proof",
    description,
    ...(replaySignal !== undefined ? { replaySignal } : {}),
  }),
}
