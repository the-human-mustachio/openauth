/**
 * Authorization-request domain shapes. The HTTP layer parses the raw
 * `/authorize` query into `AuthorizationRequest`; the domain operates on
 * that.
 */
import type { TenantId } from "./tenant"

/**
 * Parsed `/authorize` request. The HTTP layer is responsible for schema
 * validation (Zod) and for rejecting `response_type=token` per OAuth 2.1.
 *
 * `audience` and OIDC-specific fields (`prompt`, `uiLocales`, `nonce`) are
 * optional and threaded into the `FlowRecord`.
 */
export type AuthorizationRequest = {
  tenantId: TenantId
  clientId: string
  redirectUri: string
  /** OAuth 2.1: `code` only. */
  responseType: "code"
  scopes: string[]
  /** Relying party's CSRF state. Echoed back at success; opaque to the IdP. */
  state: string | null
  audience?: string
  /** Tenant-local method instance id (`MethodConfig.id`) the RP selected, if any. */
  methodId?: string
  /**
   * Relying-party PKCE challenge. Required for public clients; the framework
   * additionally requires it for any client where `ClientConfig.pkceRequired`
   * is true (default true).
   */
  codeChallenge?: string
  codeChallengeMethod?: "S256"
  /** Standard OIDC. */
  prompt?: string[]
  /** Standard OIDC. */
  uiLocales?: string[]
  /** Standard OIDC. */
  nonce?: string
  /**
   * OIDC Core §5.5 — RP-requested claims, parsed from the `claims`
   * parameter's JSON value. The library currently honors claim **names**
   * (additive, bypasses scope gating) but does not enforce the
   * `essential` / `value` / `values` qualifiers.
   */
  claimsRequest?: ClaimsRequest
}

/**
 * OIDC Core §5.5 `claims` parameter. Each section maps claim name to an
 * optional qualifier object (`{essential, value, values}`) or `null`
 * meaning "just request the claim without qualifiers".
 */
export type ClaimsRequest = {
  /** Claims to include in the `/userinfo` response. */
  userinfo?: Record<string, ClaimRequestEntry | null>
  /** Claims to include in the `id_token`. */
  id_token?: Record<string, ClaimRequestEntry | null>
}

export type ClaimRequestEntry = {
  essential?: boolean
  value?: unknown
  values?: unknown[]
}

/**
 * In-memory authorization state produced by `domain/authorize.startAuthorize`
 * when it has not yet emitted a `Response` (e.g. method selection UI was
 * not needed because only one method is configured, so the domain returns
 * the chosen state directly for the next stage to act on).
 */
export type AuthorizationState = {
  tenantId: TenantId
  flowId: string
  methodId: string
  methodKind: string
}
