/**
 * Public-surface types for `createIdP` — the user-facing options object,
 * the returned handle, the `success` callback contract, and observation
 * hook event shapes.
 */
import type { AuditLog } from "../ports/audit-log.js"
import type { ConfigStore } from "../ports/config-store.js"
import type { KeyStore } from "../ports/key-store.js"
import type { MethodStore } from "../ports/method-store.js"
import type { SessionStore } from "../ports/session-store.js"
import type { TokenStore } from "../ports/token-store.js"

import type { AuthError } from "./error.js"
import type { AuthMethodFactory } from "./method.js"
import type { Result } from "./result.js"
import type { SubjectClaim, SubjectSchema } from "./subject.js"
import type {
  StateKeyRing,
  TenantContext,
  TenantId,
  ThemeConfig,
} from "./tenant.js"

/**
 * Input handed to the user's `success` callback. The framework provides
 * everything needed to map the upstream / credential result into the
 * issued subject.
 *
 * `methodKind` tells you **which provider** produced the result (e.g.
 * `"google"`); `methodId` tells you **which tenant-local instance** of
 * that provider was used (e.g. `"google-workspace"` vs
 * `"google-personal"`). Use `methodKind` for provider-specific branches;
 * use `methodId` for instance-specific routing.
 */
export type SuccessMapInput = {
  tenant: TenantContext
  methodId: string
  methodKind: string
  /** Upstream system's stable identifier (from `MethodResult.success`). */
  providerSubject: string
  /** Typed per method via the factory's `P` generic at the call site. */
  properties: unknown
  context: Record<string, unknown> | null
}

/**
 * Optional observation hook payload — fires after the subject claim has
 * already been minted. **Does not** influence the issued subject; use it
 * for audit, analytics, side effects only.
 */
export type SuccessEvent = SuccessMapInput & {
  /** The final subject claim that became the JWT `sub`. */
  claim: SubjectClaim
}

/**
 * Optional observation hook payload — fires on a failed auth attempt.
 * Carries enough id information for operators to find the offending flow
 * / config row without leaking secrets.
 */
export type FailureEvent = {
  tenantId: TenantId | null
  clientId: string | null
  methodId?: string
  methodKind?: string
  flowId?: string
  error: AuthError
}

/**
 * Optional hook called at `/token` time, after PKCE has succeeded and
 * after the `success` callback has produced a `SubjectClaim`, but
 * **before** the access/refresh response is returned. Use this when you
 * prefer not to persist upstream tokens in the code payload itself (see
 * the "alternative split" note in the plan §"Code payload
 * confidentiality"). If it throws, the IdP responds with OAuth
 * `server_error` and the token issuance is aborted.
 */
export type PersistUpstreamTokens = (input: {
  tenant: TenantContext
  methodId: string
  methodKind: string
  providerSubject: string
  properties: unknown
  subjectClaim: SubjectClaim
}) => Promise<void>

export type IdPOptions = {
  /**
   * Tenant resolution for the first request in a flow. Not consulted on
   * callbacks — the framework recovers `(tenantId, flowId)` from the
   * MAC-bound state envelope, partitioned host, or `flowId`-in-URI
   * mechanism (see plan §"Tenant Recovery Across Redirects").
   */
  resolveTenant: (req: Request) => Promise<Result<TenantId, AuthError>>

  /** Opt-in for partitioned callback hosts (recovery mechanism #2). */
  callbackHostFor?: (tenantId: TenantId) => string

  /**
   * HMAC-SHA-256 key ring used to MAC the minimal state envelope. The
   * envelope carries only `{ tenantId, flowId, nonce, kid }` — never
   * sensitive data — so a global ring is acceptable and necessary
   * (tenant config can't be loaded until we know the tenant). Operators
   * who prefer storing the ring inside `KeyStore` can use the
   * `loadStateKeyRingFromKeyStore` helper.
   *
   * REQUIRED.
   */
  stateKeys: StateKeyRing

  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  /** Required: flow records need strong CAS / atomic delete-on-read. */
  sessionStore: SessionStore
  /** Optional but recommended for any production deployment. */
  auditLog?: AuditLog
  /** Optional — falls back to `ConfigStore` for `MethodConfig` lookups. */
  methodStore?: MethodStore

  /** Issuer URL. Function form lets multi-tenant deployments derive it per request. */
  issuerUrl: string | ((req: Request) => string)

  /**
   * Available method factories. **The KEY of this record MUST equal
   * `factory.kind`.** `createIdP` throws on construction if any key
   * disagrees with its factory's declared `kind`, with a list of
   * offending keys in the error message.
   */
  methods: Record<string, AuthMethodFactory>

  subjects: SubjectSchema

  /**
   * REQUIRED. Maps method result → issued subject. Runs at `/token` time,
   * after PKCE check, with the same conceptual role as the existing
   * `auth.success` callback in `issuer.ts`.
   */
  success: (input: SuccessMapInput) => Promise<SubjectClaim>

  theme?: ThemeConfig

  hooks?: {
    /** Observation only — does NOT influence the subject. */
    onSuccess?: (event: SuccessEvent) => Promise<void>
    onFailure?: (event: FailureEvent) => Promise<void>
  }

  /**
   * Optional escape hatch for high-sensitivity deployments — see the
   * `PersistUpstreamTokens` type doc.
   */
  persistUpstreamTokens?: PersistUpstreamTokens
}

/**
 * The returned IdP handle. `handle(req)` is the single fetch-style
 * entrypoint suitable for `export default { fetch: idp.handle }` on
 * Cloudflare Workers; the per-endpoint primitives are exposed for
 * embedding inside a larger app (e.g. mounting alongside admin routes).
 */
export type IdP = {
  handle: (req: Request) => Promise<Response>
  authorize: (req: Request) => Promise<Response>
  token: (req: Request) => Promise<Response>
  userinfo: (req: Request) => Promise<Response>
  jwks: (req: Request) => Promise<Response>
  discovery: (req: Request) => Promise<Response>
  /** Phase 8. */
  revoke?: (req: Request) => Promise<Response>
  /** Phase 8. */
  introspect?: (req: Request) => Promise<Response>
  /** Phase 8. */
  par?: (req: Request) => Promise<Response>
}
