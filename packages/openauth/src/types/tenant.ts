/**
 * Tenant model + tenant-resolution / callback-recovery types.
 *
 * Per AD1, tenancy is **not** a URL concept. A tenant is whatever the
 * user-supplied `resolveTenant(req)` says it is for an incoming request, plus
 * a deterministic callback-recovery chain (MAC-bound state, partitioned host,
 * or `flowId`-in-URI) for the post-redirect leg where the original tenant
 * signal may no longer be available.
 *
 * The minimal state envelope MACed and round-tripped through upstream
 * providers carries only `{ tenantId, flowId, nonce, kid }`. Everything else
 * lives in the server-side `FlowRecord` (see `./flow.ts`).
 */
import type { ScimConfig } from "./scim"

/**
 * Branded tenant id — **opaque to the framework**.
 *
 * The framework treats `TenantId` as a comparable string and nothing more.
 * It never parses it, never assumes a hierarchy or naming convention, never
 * imposes uniqueness rules, never knows the lifecycle of a tenant. The
 * embedding application decides what a tenant *is* (an organization, a
 * workspace, an App-Tenant tuple, a customer, …) and supplies a
 * `resolveTenant(req)` that maps incoming requests to the right key.
 *
 * Common embedding pattern when the host application has two levels of
 * scoping (e.g. `App` ⇒ `App-Tenant`): encode the tuple into the key.
 *
 * ```ts
 * // Inside the host application's resolveTenant:
 * return ok(`${app.id}:${appTenant?.id ?? "__default__"}` as TenantId)
 *
 * // Inside the host application's ConfigStore.getTenantConfig:
 * const [appId, subId] = (id as string).split(":")
 * // merge App defaults + App-Tenant overrides from your own DB ...
 * ```
 *
 * The brand exists to keep arbitrary `string` values from being passed
 * where a `TenantId` is expected; the *meaning* of the string is the host
 * application's concern.
 */
export type TenantId = string & { readonly __brand: "TenantId" }

/**
 * Cast helper for code that mints `TenantId` from a validated string. The
 * framework imposes no validation on the value — callers ensure their key
 * is non-empty and stable per partition.
 */
export const asTenantId = (value: string): TenantId => value as TenantId

/** OAuth 2.1 grant types in scope for this IdP. Implicit is intentionally absent. */
export type GrantType =
  "authorization_code" | "refresh_token" | "client_credentials"

/**
 * `MethodType` is the canonical discriminator for an `AuthMethod`. It mirrors
 * the existing provider taxonomy. The UI uses it to decide which selection /
 * form to render; the framework uses it as a routing / dispatch hint.
 */
export type MethodType =
  "oauth2" | "oidc" | "password" | "code" | "m2m" | "passkey" | "custom"

/**
 * Per-tenant configuration for a single auth method **instance**.
 *
 * `id` is the **tenant-local instance id** — the value that ends up in URLs
 * (`/<id>/*`) and that the framework dispatches by.
 *
 * `kind` is the **factory id** — the value that selects which
 * `AuthMethodFactory` builds this instance. A tenant may register multiple
 * instances of the same factory (e.g. one Google Workspace SSO and one
 * consumer Google Sign-In) by giving each instance a unique `id` while
 * sharing a `kind`.
 *
 * `type` is the `MethodType` discriminator the UI uses. The framework
 * verifies it agrees with the factory's declared type at load time.
 *
 * `config` is the tenant-supplied configuration blob. The framework validates
 * it against the factory's Zod `configSchema` before any handler runs.
 */
export type MethodConfig = {
  id: string
  kind: string
  type: MethodType
  enabled: boolean
  config: Record<string, unknown>
}

/** Optional theme metadata. Schema expanded in later phases. */
export type ThemeConfig = {
  primary?: string
  logo?: string
  favicon?: string
  background?: string
  font?: string
}

/**
 * Registered OAuth client of this IdP (an app, SPA, mobile, M2M).
 *
 * Phase 8: split into a discriminated union so misconfiguration is a type
 * error, not a runtime check. The runtime in `domain/authorize.ts` still
 * enforces PKCE for public clients defensively, but hosts will see the
 * problem at compile time.
 *
 * - **Public clients** (SPAs, mobile apps, native apps): no client secret;
 *   `pkceRequired` is the literal `true`. PKCE is non-negotiable per
 *   OAuth 2.1 BCP §2.1.1.
 * - **Confidential clients** (server-side apps, M2M): `secretHash` is
 *   required (this used to be optional, in practice always set). PKCE
 *   recommended but may be disabled by the host.
 */
export type ClientConfig = PublicClientConfig | ConfidentialClientConfig

export type PublicClientConfig = {
  id: string
  name: string
  type: "public"
  redirectUris: string[]
  grantTypes: GrantType[]
  scopes: string[]
  /** Must be `true` for public clients per OAuth 2.1 §2.1.1. */
  pkceRequired: true
  /**
   * Registered URIs to which `/end_session` may redirect after RP-initiated
   * logout (OIDC RP-Initiated Logout 1.0 §2). Exact-match. If absent, the
   * `/end_session` endpoint refuses any `post_logout_redirect_uri`.
   */
  postLogoutRedirectUris?: string[]
  /**
   * RFC 9126 §2: when `true`, the client MUST use Pushed Authorization
   * Requests; a direct `GET /authorize` call without `request_uri` is
   * rejected with `invalid_request`.
   */
  requirePushedAuthorizationRequests?: boolean
  /**
   * OIDC Core §8.1 — when set, the subject identifier (`sub`) is derived
   * as a pairwise pseudonym keyed by this string. Two clients sharing
   * the same `sectorIdentifier` will see the same `sub`; different
   * values yield different `sub`s for the same end user. Absent =
   * public subject (sub is identical across all RPs).
   */
  sectorIdentifier?: string
  /** Phase 8. */
  dpopRequired?: boolean
}

export type ConfidentialClientConfig = {
  id: string
  name: string
  type: "confidential"
  /** Hash of the client secret. Required for confidential clients. */
  secretHash: string
  redirectUris: string[]
  grantTypes: GrantType[]
  scopes: string[]
  /**
   * Default true. Disabling it is permitted for confidential clients but
   * strongly discouraged; OAuth 2.1 §2.1.1 recommends PKCE for every client.
   */
  pkceRequired: boolean
  /**
   * Registered URIs to which `/end_session` may redirect after RP-initiated
   * logout (OIDC RP-Initiated Logout 1.0 §2). Exact-match.
   */
  postLogoutRedirectUris?: string[]
  /**
   * RFC 9126 §2: when `true`, the client MUST use Pushed Authorization
   * Requests; a direct `GET /authorize` call without `request_uri` is
   * rejected with `invalid_request`.
   */
  requirePushedAuthorizationRequests?: boolean
  /**
   * OIDC Core §8.1 — see `PublicClientConfig.sectorIdentifier` for
   * semantics. Same field; duplicated on each branch because the
   * `ClientConfig` discriminated union doesn't share optional fields.
   */
  sectorIdentifier?: string
  /** Phase 8. */
  dpopRequired?: boolean
}

export type TenantConfig = {
  id: TenantId
  displayName: string
  clients: ClientConfig[]
  methods: MethodConfig[]
  theme?: ThemeConfig
  /** Set when the tenant needs cross-subdomain SSO. */
  cookieDomain?: string
  /** Override default refresh-token TTL (seconds). */
  refreshTtl?: number
  /** Override default access-token TTL (seconds). */
  accessTtl?: number
  /**
   * SCIM 2.0 provisioning for this tenant. Absent or `enabled: false` ⇒
   * `/scim/v2/*` answers 403 for this tenant.
   *
   * Tenant-level rather than a `MethodConfig` because SCIM is not an
   * auth method — no `/authorize`, no flow, no user agent. See
   * `SCIM-AD5` in `docs/plans/claude/scim-plan.md`.
   */
  scim?: ScimConfig
}

/**
 * Per-request tenant context handed to methods and the user-supplied
 * `success` callback. `request.raw` is the Web Fetch `Request` the framework
 * received; `request.custom` is whatever the host returned from the
 * `IdPOptions.buildCustomContext` hook (request id, decoded JWT claims, mTLS
 * cert info, geo hints — anything per-request that methods or `success`
 * should see). Without the hook the blob is `{}`. The same blob is also
 * persisted on the `FlowRecord` at `/authorize` time so it survives the
 * upstream redirect and re-presents on the callback side.
 */
export type TenantContext = {
  id: TenantId
  config: TenantConfig
  request: {
    raw: Request
    custom: Record<string, unknown>
  }
}

/**
 * Outcome of the framework's tenant-recovery chain, evaluated **before**
 * `resolveTenant` runs on the incoming request. Each non-`fresh-request`
 * variant carries a `flowId`; the framework consumes the matching
 * `FlowRecord` and dispatches without consulting `resolveTenant`.
 *
 * Order of evaluation (see plan §"Tenant Recovery Across Redirects"):
 *   1. If `callbackHostFor` configured AND host matches a known tenant:
 *        a. `state` MAC-verifies → host-plus-mac
 *        b. `flowId` in URI       → host-plus-uri
 *        c. otherwise              → invalid_request, audit unrecoverable_flow
 *   2. Else if `state` MAC-verifies → mac-state
 *   3. Else if `flowId` in registered URI path/query → flow-id-in-uri
 *   4. Else → fresh-request → call user's `resolveTenant(req)`
 */
export type TenantRecovery =
  | { kind: "mac-state"; tenantId: TenantId; flowId: string }
  | { kind: "host-plus-uri"; tenantId: TenantId; flowId: string }
  | { kind: "host-plus-mac"; tenantId: TenantId; flowId: string }
  | { kind: "flow-id-in-uri"; tenantId: TenantId; flowId: string }
  | { kind: "fresh-request" }

/**
 * Minimal envelope MACed into the `state` query parameter. Intentionally
 * tiny — under 256 base64url bytes — so it stays clear of provider URL
 * limits. **No sensitive data must ever be added here.** Everything else
 * lives in the server-side `FlowRecord`.
 */
export type StateEnvelope = {
  tenantId: TenantId
  flowId: string
  /** Per-flow nonce. Distinct from the relying party's `state` param. */
  nonce: string
  /** Key id of the HMAC key used to mint this envelope (`StateKeyRing` lookup). */
  kid: string
}

/**
 * HMAC-SHA-256 key entry used to mint / verify the `state` envelope MAC.
 * The 32-byte key is global (shared across IdP instances) — recovery has to
 * work before tenant config is loaded, so per-tenant keys would create a
 * bootstrap problem.
 */
export type StateKey = {
  kid: string
  /** 32 raw bytes. */
  key: Uint8Array
}

/**
 * State-MAC key ring with overlap-based rotation. `active` mints new state;
 * any key in `verify` accepts existing state during its overlap window.
 *
 * Rotation cadence: monthly. The overlap window must be at least as long as
 * the flow-record TTL (default 10 minutes); a 1-hour overlap is the
 * recommended default. New keys are added to `verify` first, promoted to
 * `active` on the next rotation, then dropped from `verify` after overlap.
 */
export type StateKeyRing = {
  active: StateKey
  /** Includes `active` plus any previous keys still inside their overlap window. */
  verify: ReadonlyArray<StateKey>
}
