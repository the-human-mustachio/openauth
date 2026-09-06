/**
 * Public-surface types for `createIdP` — the user-facing options object,
 * the returned handle, the `success` callback contract, and observation
 * hook event shapes.
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { MethodStore } from "../ports/method-store"
import type { ScimDirectory } from "../ports/scim-directory"
import type { SessionStore } from "../ports/session-store"
import type { TokenStore } from "../ports/token-store"

import type { AuthError } from "./error"
import type { AnyAuthMethodFactory } from "./method"
import type { Result } from "./result"
import type { SubjectClaim, SubjectSchema } from "./subject"
import type {
  ClientConfig,
  StateKeyRing,
  TenantContext,
  TenantId,
  ThemeConfig,
} from "./tenant"
import type { PickerContext, PickerMethod } from "./picker"

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
 * Input to the optional `IdPOptions.onLogout` hook.
 *
 * Fires when an upstream provider notifies this IdP that a federated
 * session has ended — today, a SAML front-channel `LogoutRequest`
 * delivered to the SP's SLS endpoint. By the time this runs the library
 * has already cryptographically verified the upstream logout message
 * (XML-DSig via the SAML method), so the hook is purely the host's
 * teardown point.
 *
 * The library deliberately does **not** know which OIDC `subject` an
 * upstream identifier (`nameId`) maps to — that mapping lives in the
 * host's `success` callback, not the library. So the host clears its
 * own session and returns the subject (if any) whose library-issued
 * tokens should be revoked; the library then runs the same
 * `revokeAllForSubject` primitive `/end_session` uses. Returning
 * nothing skips library-side revocation (the host handled everything,
 * or there is nothing to revoke).
 *
 * Method-agnostic on purpose: any federation method that can verify an
 * upstream logout signal reuses this. SAML SLO is the first caller;
 * OIDC back-channel logout would be the next.
 */
export type LogoutEventInput = {
  tenant: TenantContext
  methodId: string
  methodKind: string
  /** What kind of upstream logout this is. Extensible discriminant. */
  reason: "upstream_slo"
  /**
   * Upstream subject identifier from the verified logout message
   * (SAML `LogoutRequest/NameID`). Absent if the message omitted it.
   */
  nameId?: string
  /**
   * Upstream session index from the verified logout message
   * (SAML `SessionIndex`), when present. Lets a host that tracks
   * per-session state scope its teardown.
   */
  sessionIndex?: string
}

/**
 * Return of `IdPOptions.onLogout`. `revokeSubject` names the OIDC
 * subject whose library-issued refresh tokens the library should
 * revoke (the host resolves it from `nameId` — only the host has that
 * map). Omit / return nothing to skip library-side revocation.
 */
export type LogoutHookResult = { revokeSubject?: string } | void

/**
 * Fired when tokens are minted, naming the derived subject id.
 *
 * This is the only way a host can learn `subjectId` — the value the
 * library signs as `sub`, and the key `TokenStore.revokeBySubject` and
 * `revokeAllForSubject` take. It is derived inside the library from the
 * claim and the receiving client's `sectorIdentifier`, so without this
 * hook a host holds a revocation primitive it can never call, and
 * `onLogout`'s `revokeSubject` has no map to resolve against.
 *
 * That matters because refresh rotation never re-consults the host:
 * `refreshTokens` mints from the claim captured on the stored payload.
 * Revoking the chain is the only way to stop an offboarded user's tokens
 * from being renewed indefinitely.
 *
 * **A principal maps to many subject ids, not one.** Record them; do not
 * overwrite. Two reasons, both silent if you assume otherwise:
 *
 *  - **Pairwise** — with `ClientConfig.sectorIdentifier` set, derivation
 *    mixes the sector in (OIDC Core §8.1), so the same person has a
 *    distinct `sub` per sector. Revoking one leaves the others minting.
 *  - **Claim contents** — derivation hashes `claim.properties`. If your
 *    `success()` returns anything mutable (an email, a role), the subject
 *    id changes when that value changes, and chains issued under the old
 *    one survive. Returning a single immutable id is the way to avoid
 *    this; OIDC Core §2 wants `sub` never reassigned.
 *
 * Runs **before** the refresh token is persisted, so throwing aborts
 * issuance with `server_error` and leaves no chain behind. That is
 * deliberate: recording the mapping after the token is durable would let
 * a hook failure produce exactly the unrevokable token this exists to
 * prevent. Like `success` and `persistUpstreamTokens`, and unlike
 * `AuditLog`, a failure here stops the grant.
 */
export type OnTokenIssued = (input: {
  tenant: TenantContext
  /** Client the tokens were minted for. */
  clientId: string
  /**
   * The `sub` of the issued access token — the key `revokeBySubject` and
   * `revokeAllForSubject` take.
   */
  subjectId: string
  /**
   * The claim your `success()` (or token-exchange audience mapping)
   * returned, already validated against `subjects`. Use it to attribute
   * `subjectId` to one of your own principals.
   */
  claim: SubjectClaim
  /**
   * Refresh-token family, for `TokenStore.revokeFamily`. Absent when the
   * grant issued no refresh token (`client_credentials`, RFC 6749
   * §4.4.3), because then there is no chain to revoke.
   */
  family?: string
}) => Promise<void> | void

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

/**
 * Optional hook called for RFC 8693 token-exchange requests at
 * `/token`. The host decides whether the authenticated subject can
 * obtain a token scoped to `request.audience` (a new tenant), and
 * returns either:
 *
 *   - the `SubjectClaim` representing the subject's identity at the
 *     new audience (often the same shape but different `properties` —
 *     e.g. a different role), or
 *   - an `AuthError` (typically `authError.invalidTarget(...)` if the
 *     subject can't access that audience).
 *
 * If this hook is not supplied, token-exchange requests are rejected
 * with `unsupported_grant_type`. This is the graceful-degradation
 * default — the grant simply isn't enabled.
 *
 * The library does NOT inspect the audience string; it's an opaque
 * `TenantId` that the host's `ConfigStore` must be able to resolve.
 */
export type ExchangeAudience = (
  currentClaim: SubjectClaim,
  request: {
    /** The target tenant id (RFC 8693 `audience`). Opaque to the library. */
    audience: string
    /** Subset of subject_token scopes the caller asked for. */
    requestedScopes?: string[]
    /** The authenticated client doing the exchange. */
    clientId: string
    /** Tenant the subject_token came from. */
    fromTenantId: string
  },
) => Promise<SubjectClaim | AuthError>

/**
 * RFC 7591 Dynamic Client Registration request body, normalized to the
 * library's type system. The framework's `/register` handler parses the
 * raw JSON, validates structure, then calls the host's `registerClient`
 * hook with this shape. The host owns persistence — writing through its
 * own `ConfigStore` — and returns the final `ClientConfig`.
 */
export type RegisterClientRequest = {
  client_name?: string
  redirect_uris: string[]
  /** RFC 7591 §2 — defaults to `["authorization_code"]`. */
  grant_types?: string[]
  /** RFC 7591 §2 — defaults to `["code"]`. */
  response_types?: string[]
  /** RFC 7591 §2 — `"none"` = public client, otherwise confidential. */
  token_endpoint_auth_method?:
    "none" | "client_secret_basic" | "client_secret_post"
  scope?: string
  /** OIDC RP-Initiated Logout 1.0 §2. */
  post_logout_redirect_uris?: string[]
  /** OIDC Core §8.1. */
  sector_identifier_uri?: string
  /** Free-form metadata the host may interpret. */
  contacts?: string[]
}

/**
 * RFC 7591 §3.2.1 response body. Returned verbatim from `/register` when
 * the host hook produces a `ClientConfig`. `client_secret` is included
 * only for confidential clients; public clients omit it.
 */
export type RegisterClientResponse = {
  client_id: string
  client_secret?: string
  client_id_issued_at: number
  client_secret_expires_at?: number
  redirect_uris: string[]
  grant_types?: string[]
  response_types?: string[]
  token_endpoint_auth_method?: string
  client_name?: string
}

/**
 * Optional Dynamic Client Registration hook. Hosts that want to expose
 * RFC 7591 client provisioning supply this; the framework validates the
 * wire format and mints credentials, then defers **persistence** to the
 * host. If absent, the `/register` endpoint returns `invalid_request` so
 * RPs receive a clear "not enabled" signal rather than a 404.
 *
 * The library owns credential generation — entropy, hashing, and the
 * `ClientConfig` discriminated union, which requires `pkceRequired: true`
 * as a literal on public clients and a `secretHash` on confidential ones.
 * Those are protocol and security concerns, and making every host
 * reimplement them is how they get done wrong. The host owns the table:
 * write `client` through your own `ConfigStore` and return it.
 *
 * Before 0.14.0 this hook received only `{ tenant, request }` and the
 * framework discarded what it had generated, so hosts had to mint their
 * own — contradicting both this doc comment and `ARCHITECTURE.md`.
 *
 * Return the config you actually persisted. Adjusting it first is fine
 * (narrowing `scopes`, substituting your own `id`); if you replace `id`
 * or `secretHash`, return the matching plaintext as `secret` so the RP
 * receives something that works.
 */
export type RegisterClient = (input: {
  tenant: TenantContext
  request: RegisterClientRequest
  /**
   * Framework-minted `ClientConfig`, ready to persist as-is. Public
   * clients carry `pkceRequired: true`; confidential clients carry
   * `secretHash` for `secret` below.
   */
  client: ClientConfig
  /**
   * Plaintext secret matching `client.secretHash`. Present only for
   * confidential clients. Return it in the result so the RP can record
   * it — this is the only time it exists.
   */
  secret?: string
}) => Promise<Result<{ client: ClientConfig; secret?: string }, AuthError>>

/**
 * Optional override for the default provider picker shown when an
 * `/authorize` request has multiple enabled methods and no `method_id`.
 *
 * The library ships a minimal styled default (see `src/ui/picker.ts`);
 * supply this to render a fully custom selection screen. The returned
 * `Response` is sent as-is; the framework applies `cache-control: no-store`
 * unless the response already sets a `Cache-Control` header.
 */
export type RenderPicker = (
  methods: PickerMethod[],
  ctx: PickerContext,
) => Response | Promise<Response>

export type IdPOptions = {
  /**
   * Tenant resolution for the first request in a flow. Not consulted on
   * callbacks — the framework recovers `(tenantId, flowId)` from the
   * MAC-bound state envelope, partitioned host, or `flowId`-in-URI
   * mechanism (see plan §"Tenant Recovery Across Redirects").
   */
  resolveTenant: (req: Request) => Promise<Result<TenantId, AuthError>>

  /**
   * Opt-in for partitioned callback hosts (recovery mechanism #2).
   *
   * Returns the hostname a given tenant's callbacks arrive on, so the
   * tenant is recoverable from the `Host` header before the state
   * envelope is verified.
   *
   * **The issuer's mount prefix still applies to the returned host.** If
   * `issuerUrl` is `https://example.com/idp`, a tenant host of
   * `acme.example.com` produces `https://acme.example.com/idp/cb/<id>`.
   * This option varies the *authority* of one deployment — those hosts
   * are served by this same service behind the same proxy, so they share
   * its mount. A deployment needing partitioned hosts mounted differently
   * from the issuer is describing two mounts, which one `issuerUrl`
   * cannot express; a second option must not be added to paper over it.
   */
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
  /**
   * The host's user directory, as SCIM needs to see it. Supply it to
   * serve `/scim/v2/*`; omit it and those routes answer 501 regardless
   * of per-tenant config.
   *
   * The library owns the SCIM protocol and stores no user data — every
   * read and write goes through this port to the host's own tables. See
   * `SCIM-AD2` in `docs/plans/claude/scim-plan.md` and
   * `INTEGRATION.md` § SCIM.
   */
  scimDirectory?: ScimDirectory

  /** Issuer URL. Function form lets multi-tenant deployments derive it per request. */
  issuerUrl: string | ((req: Request) => string)

  /**
   * Available method factories. **The KEY of this record MUST equal
   * `factory.kind`.** `createIdP` throws on construction if any key
   * disagrees with its factory's declared `kind`, with a list of
   * offending keys in the error message.
   */
  methods: Record<string, AnyAuthMethodFactory>

  subjects: SubjectSchema

  /**
   * REQUIRED. Maps method result → issued subject. Runs at `/token` time,
   * after PKCE check, with the same conceptual role as the existing
   * `auth.success` callback in `issuer.ts`.
   */
  success: (input: SuccessMapInput) => Promise<SubjectClaim>

  theme?: ThemeConfig

  /**
   * Optional hook fired when an upstream provider signals that a
   * federated session ended — SAML front-channel Single Logout today.
   * The library has already verified the signed logout message; this
   * hook is where the host tears down its own session and names the
   * OIDC subject (if any) whose library-issued tokens to revoke. See
   * the `LogoutEventInput` / `LogoutHookResult` type docs.
   *
   * Unlike `AuditLog` (observation only) this hook **influences**
   * library behaviour — its return drives token revocation — so it sits
   * at the top level alongside `success`.
   *
   * Absent ⇒ the library still verifies the logout, emits a
   * `session_logout` audit event, and returns the protocol
   * `LogoutResponse`, but performs no token revocation (it cannot map
   * the upstream id to a subject without the host).
   *
   * If it throws, the SLS endpoint fails closed with an internal error
   * rather than acknowledging a logout it could not fully process.
   */
  onLogout?: (
    input: LogoutEventInput,
  ) => Promise<LogoutHookResult> | LogoutHookResult

  /**
   * Optional escape hatch for high-sensitivity deployments — see the
   * `PersistUpstreamTokens` type doc.
   */
  persistUpstreamTokens?: PersistUpstreamTokens

  /**
   * Optional hook fired as tokens are minted, carrying the derived
   * `subjectId` alongside the claim it came from.
   *
   * Supply this if you need to revoke a user's tokens later — on
   * offboarding, deactivation, or a membership change. `subjectId` is
   * computed inside the library and appears nowhere else, so without
   * this hook `TokenStore.revokeBySubject` / `revokeAllForSubject` are
   * uncallable and `onLogout`'s `revokeSubject` has nothing to resolve
   * against. See {@link OnTokenIssued} — in particular, one principal
   * has many subject ids and they must be accumulated, not overwritten.
   *
   * Throwing aborts the grant; it runs before the refresh token is
   * persisted so no unrecorded chain can survive a failure.
   */
  onTokenIssued?: OnTokenIssued

  /**
   * Optional RFC 8693 token-exchange hook. If absent, exchange
   * requests at `/token` return `unsupported_grant_type`. See the
   * `ExchangeAudience` type doc for the contract.
   */
  exchangeAudience?: ExchangeAudience

  /**
   * Optional override for the default provider picker. See `RenderPicker`.
   */
  renderPicker?: RenderPicker

  /**
   * Optional RFC 7591 Dynamic Client Registration hook. See
   * `RegisterClient` for the contract. When absent, `/register` rejects
   * with `invalid_request: "dynamic client registration is not enabled"`.
   */
  registerClient?: RegisterClient

  /**
   * Optional hook that builds the `TenantContext.request.custom` blob for
   * each request the framework processes (the initial `/authorize`, the
   * `/cb/*` callback, and any subsequent direct token endpoint hit).
   *
   * The returned record flows through to methods' `MethodContext`, to the
   * `success` callback's `SuccessMapInput.context`, and to authorize-time
   * `FlowRecord.context` (which is then re-presented on the
   * `/cb/*` side as the flow proceeds). Typical contents: a request id,
   * decoded JWT claims from a host edge layer, mTLS cert info, geo
   * hints — anything per-request the host wants methods or `success` to
   * see.
   *
   * Without this hook, `tenant.request.custom` is `{}` and
   * `SuccessMapInput.context` is `null`. There is no semantic difference
   * between an absent hook and one that returns `{}`.
   */
  buildCustomContext?: (
    req: Request,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>

  /**
   * Optional vendor scope → claim-names map. Merged on top of OIDC Core
   * §5.4 when building the id_token + `/userinfo` response. Lets a host
   * expose its own identity vocabulary (`tenant_id`, `org_role`, etc.)
   * via custom scope names. The standard §5.4 mapping always wins on
   * collision, so an entry for `email` is silently ignored.
   *
   * Per-client scope allowlist still applies — a client must list a
   * custom scope in `ClientConfig.scopes` to be allowed to request it.
   *
   * ```ts
   * customScopeClaims: {
   *   tenant: ["tenant_id", "tenant_role", "tenant_roles"],
   *   org: ["organization_id", "org_role"],
   * }
   * ```
   */
  customScopeClaims?: Record<string, ReadonlyArray<string>>

  /**
   * Optional override for the framework's `Set-Cookie` defaults.
   *
   * Production deployments should rely on the built-in defaults
   * (`secure: true`, no domain, `path: "/"`). Local development over plain
   * HTTP — where Chrome rejects `Secure` cookies — can pass
   * `cookies: { secure: false }` so the `idp.flow` / `auth.*` cookies
   * round-trip on `localhost`. `domain` and `path` are passed through to
   * every framework-issued cookie that doesn't set them itself.
   */
  cookies?: {
    secure?: boolean
    domain?: string
    path?: string
  }
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
  revoke: (req: Request) => Promise<Response>
  introspect: (req: Request) => Promise<Response>
  /** OIDC RP-Initiated Logout 1.0. */
  endSession: (req: Request) => Promise<Response>
  /** RFC 9126 Pushed Authorization Requests. */
  par: (req: Request) => Promise<Response>
  /** RFC 7591 Dynamic Client Registration. */
  register: (req: Request) => Promise<Response>
}
