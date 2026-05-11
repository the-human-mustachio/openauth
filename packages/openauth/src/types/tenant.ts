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

/**
 * Branded tenant id. Treat as an opaque, comparable string; the brand exists
 * to keep arbitrary `string` values from being passed where a `TenantId` is
 * expected.
 */
export type TenantId = string & { readonly __brand: "TenantId" }

/** Cast helper for code that mints `TenantId` from a validated string. */
export const asTenantId = (value: string): TenantId => value as TenantId

/** OAuth 2.1 grant types in scope for this IdP. Implicit is intentionally absent. */
export type GrantType =
  | "authorization_code"
  | "refresh_token"
  | "client_credentials"

/**
 * `MethodType` is the canonical discriminator for an `AuthMethod`. It mirrors
 * the existing provider taxonomy. The UI uses it to decide which selection /
 * form to render; the framework uses it as a routing / dispatch hint.
 */
export type MethodType =
  | "oauth2"
  | "oidc"
  | "password"
  | "code"
  | "m2m"
  | "passkey"
  | "custom"

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

/** Registered OAuth client of this IdP (an app, SPA, mobile, M2M). */
export type ClientConfig = {
  id: string
  name: string
  type: "public" | "confidential"
  /**
   * Hash of the client secret for confidential clients. Null / absent for
   * public clients (which must use PKCE).
   */
  secretHash?: string
  redirectUris: string[]
  grantTypes: GrantType[]
  scopes: string[]
  /** Default true. False is only permissible for confidential clients. */
  pkceRequired: boolean
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
}

/**
 * Per-request tenant context handed to methods and the user-supplied
 * `success` callback. `request.raw` is the Web Fetch `Request` the framework
 * received; `request.custom` is whatever the user attached during
 * `resolveTenant` (e.g. a request id, decoded JWT claims, mTLS cert info).
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
