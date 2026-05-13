/**
 * `FlowRecord` — the single server-side source of truth for an in-flight
 * authorization. Persisted in `SessionStore` between `/authorize` and the
 * upstream provider's callback.
 *
 * The `state` envelope round-tripped through the upstream provider carries
 * **only** `{ tenantId, flowId, nonce, kid }`. Sensitive data
 * (`clientPkce`, `appRedirectUri`, scopes, audience, etc.) lives here and
 * here only.
 *
 * Lifecycle:
 *   1. Create — at `/authorize`, after schema validation + tenant resolve.
 *   2. Update — when a method handler returns `{ kind: "challenge",
 *      saveMethodState }`, the framework merges `saveMethodState` into
 *      `methodState` and persists **before** sending the upstream redirect
 *      response.
 *   3. Consume — on callback, atomically (`consumeFlow`) — single delete-on-read.
 *   4. Snapshot + dispose — on `success`, the framework snapshots the fields
 *      needed at `/token` into the auth-code payload; `methodState` is
 *      dropped.
 */
import type { ClaimsRequest } from "./authorization"
import type { TenantId } from "./tenant"

export type FlowRecord = {
  flowId: string
  tenantId: TenantId

  /** Tenant-local instance id (`MethodConfig.id`), e.g. `"google-workspace"`. */
  methodId: string
  /** Factory kind (`MethodConfig.kind`), e.g. `"google"`. */
  methodKind: string

  /** Relying party's registered client id. */
  clientId: string
  /** Final redirect to the relying party. */
  appRedirectUri: string
  /** Full expected request pathname for this specific flow on callback. */
  callbackPath: string
  /** Expected request host on callback. */
  callbackHost: string
  /** Relying party's `state` param, echoed back at success. */
  appState: string | null
  /** Scopes requested at `/authorize`. */
  scopes: string[]
  /**
   * OAuth 2.1 — `code` only. Implicit (`response_type=token`) is removed; see
   * plan §"OAuth 2.1 — `code` only".
   */
  responseType: "code"
  audience?: string
  /** Standard OIDC prompt values (`none`, `login`, `consent`, …). */
  prompt?: string[]
  uiLocales?: string[]
  /**
   * Per-flow CSRF nonce stamped into the `state` envelope. Distinct from
   * `appState`. Compared at callback against the consumed record.
   */
  nonce: string
  /**
   * Relying party's OIDC `nonce` parameter (OIDC Core §3.1.2.1). Distinct
   * from `nonce` (which is the framework's CSRF nonce for state-MAC
   * binding). When present, must be echoed in the issued `id_token`
   * (OIDC Core §2). Snapshotted into `CodePayload.appNonce` at success.
   */
  appNonce?: string
  /** OIDC Core §5.5 — RP-requested claims, parsed at `/authorize`. */
  claimsRequest?: ClaimsRequest
  /**
   * Relying-party → IdP PKCE. The RP generates the verifier and sends the
   * challenge to `/authorize`. Verified at `/token`.
   * Required for public clients.
   */
  clientPkce?: { challenge: string; method: "S256" }

  /**
   * Method-private state — opaque to the framework, typed via the
   * `AuthMethod<P, S>` generic on the owning method. Examples:
   *   - OAuth provider:  `{ upstreamPkceVerifier, upstreamState }`
   *   - OIDC provider:   `{ upstreamPkceVerifier, upstreamNonce }`
   *   - Passkey:         `{ challenge, allowedCredentialIds }`
   *   - Password:        typically `null` (no upstream callback)
   *
   * Methods do not write this directly; they request a merge via
   * `MethodResult.challenge.saveMethodState`.
   */
  methodState?: unknown

  /** User's `requestContext` snapshot, if any. */
  context?: Record<string, unknown>

  createdAt: number
  /**
   * Pre-callback lifetime — covers upstream login, MFA, consent, mobile app
   * switching, etc. Default 10 minutes. Distinct from the auth-code TTL
   * (60 s) which covers the post-callback span.
   */
  expiresAt: number
}
