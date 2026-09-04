# Architecture — `@_mustachio/openauth`

This document describes the rebuilt IdP architecture introduced by the plan
in `docs/plans/claude/idp-rebuild-plan.md`. It is the onboarding doc for
future-phase work; the plan remains authoritative for sequencing and
decisions.

Phase 1 ships **types only** — every interface described here is realized
as a TypeScript declaration under `src/types/` and `src/ports/`. Runtime
behavior (domain functions, HTTP adapter, methods, real adapters) lands in
later phases.

## Mental model

```
              ┌──────────────────────────────────────────────────┐
              │                  HTTP adapter                    │   Phase 3
              │  • parses Request → AuthorizationRequest         │
              │  • applies CookiePolicy / sanitizes Response     │
              │  • runs tenant recovery, then resolveTenant      │
              └────────────┬─────────────────────────────────────┘
                           │  pure data (no Hono types)
              ┌────────────▼─────────────────────────────────────┐
              │                    Domain                        │   Phase 2
              │  authorize / token / refresh / revoke / …        │
              │  pure (input, ports) → Promise<Result<output>>   │
              └────────────┬─────────────────────────────────────┘
                           │  port interfaces
              ┌────────────▼─────────────────────────────────────┐
              │                  Ports                           │   Phase 1
              │  ConfigStore  TokenStore  SessionStore  KeyStore │
              │  MethodStore  AuditLog                           │
              └────────────┬─────────────────────────────────────┘
                           │  concrete adapters
              ┌────────────▼─────────────────────────────────────┐
              │                Adapters                          │   Phase 2 (memory)
              │  memory  d1  kv  durable-object  dynamo  postgres │   Phase 6 (rest)
              │  kms                                              │
              └──────────────────────────────────────────────────┘
```

Methods (`src/methods/`) plug in alongside this stack. A method is **data +
handler functions**, not a framework module. The allowed import set is:

- `src/types/` — every public type (`AuthMethod`, `MethodContext`, …).
- `src/domain/crypto` — `base64url`, `sha256`, `randomBytes`,
  `timingSafeEqualStr`, `utf8`. The cryptographic primitives are shared
  with the domain layer and would be needlessly duplicated otherwise.
- `src/ui/forms` — `renderForm` and friends for the default credential UI.
- Sibling `src/methods/*` modules (e.g. `methods/password-hash`).
- Web Fetch `Request` / `Response` and method-specific third-party
  libraries (`zod`, `@simplewebauthn/server`).

Methods MUST NOT import from `src/http/`, `src/adapters/`, or
`src/ports/`. The HTTP adapter mounts each tenant's configured methods
under `/<MethodConfig.id>/*` (the tenant-local instance id, not the
factory kind).

## Type system — what lives where

| File                     | Purpose                                                                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `types/result.ts`        | `Result<T, E>` + `ok` / `err` / `isOk` / `isErr` helpers. The domain returns these instead of throwing.                                                                               |
| `types/error.ts`         | `AuthError` closed taxonomy + `authError.*` constructor helpers. Maps 1:1 to OAuth 2.0 codes plus framework-internal codes.                                                           |
| `types/tenant.ts`        | `TenantId` brand, `TenantConfig`, `ClientConfig`, `MethodConfig`, `MethodType`, `TenantContext`, `TenantRecovery`, `StateKeyRing`.                                                    |
| `types/flow.ts`          | `FlowRecord` — single source of truth for in-flight authorization state.                                                                                                              |
| `types/method.ts`        | `AuthMethod`, `AuthMethodFactory`, `MethodContext`, `MethodResult`, `SetCookie`, `CachePolicy`. **Zero framework imports.**                                                           |
| `types/authorization.ts` | `AuthorizationRequest`, `AuthorizationState`, `ClaimsRequest` (OIDC Core §5.5).                                                                                                       |
| `types/token.ts`         | `CodePayload`, `AccessTokenClaims`, `IdTokenClaims`, `ScopedProfileClaims`, `AddressClaim`, `RefreshTokenPayload`, `TokenResponse`.                                                   |
| `types/subject.ts`       | `SubjectSchema`, `SubjectPayload`, `SubjectClaim`. Library-agnostic via Standard Schema v1; Zod recommended (AD4).                                                                    |
| `types/idp.ts`           | Public surface: `IdPOptions`, `IdP`, `SuccessMapInput`, `SuccessEvent`, `FailureEvent`, `PersistUpstreamTokens`, `RegisterClient`, `RegisterClientRequest`, `RegisterClientResponse`. |
| `ports/*.ts`             | Port interfaces. Each carries consistency JSDoc; the canonical contract table is in `ports/CONSISTENCY.md`.                                                                           |

## The `id` / `kind` split

Every runtime contract that names a method carries **two** identifiers:

- `id` — **tenant-local instance id** (from `MethodConfig.id`). The
  framework dispatches URL routes by this value. URLs look like
  `/<id>/authorize`, `/<id>/callback`.
- `kind` — **factory id** (from `MethodConfig.kind`). Selects which
  `AuthMethodFactory` builds the instance.

Why both: a tenant may register multiple instances of the same factory.
A typical example is a tenant that wants both Google Workspace SSO
(`{ kind: "google", id: "google-workspace" }`) and consumer Google
Sign-In (`{ kind: "google", id: "google-personal" }`), each with its own
client id and scopes. The URL space and the cache key are
**`MethodConfig.id`**; the factory lookup is **`MethodConfig.kind`**.

Both ids flow through `FlowRecord`, `CodePayload`, `SuccessMapInput`,
`AuditEvent`, and the `AuthMethod` returned by `factory.build`. Use
`methodKind` for provider-specific logic in the `success` callback; use
`methodId` for instance-specific routing.

## Tenant recovery across redirects

`resolveTenant(req)` works for the **first** request in a flow (subdomain,
header, JWT, mTLS, etc.). It does **not** work reliably for the upstream
provider's callback — by the time Google redirects the user back, the
original tenant signal may be gone.

The framework runs an **ordered recovery chain** before `resolveTenant`:

1. If `callbackHostFor` is configured AND the request host matches a known
   tenant:
   - `state` MAC-verifies → `host-plus-mac`
   - else `flowId` in URI → `host-plus-uri`
   - else → reject (`invalid_request`, audit
     `unrecoverable_flow`)
2. Else if `state` MAC-verifies → `mac-state`
3. Else if `flowId` in registered URI path / query → `flow-id-in-uri`
4. Else → `fresh-request` → call user's `resolveTenant(req)`

Each non-`fresh-request` outcome carries `(tenantId, flowId)`. The
framework calls `SessionStore.consumeFlow(flowId)` exactly once, then runs
the **state-flow consistency check** before dispatching the method
callback:

```
state.tenantId === flow.tenantId          // tenant binding
state.nonce    === flow.nonce             // CSRF
request.host   === flow.callbackHost      // host binding
request.path   === flow.callbackPath      // exact-match after normalization
```

Any mismatch → `invalid_request`, audit
`flow_replay_attempt` / `flow_tenant_mismatch` /
`flow_callback_mismatch`.

### State on POST-binding callbacks

The MAC envelope normally rides `?state=` on the upstream redirect.
POST-binding callbacks carry it in the form body instead: OAuth
`response_mode=form_post` uses `state`; SAML's HTTP-POST binding uses
`RelayState`. `handleCallback` resolves it via `extractCallbackState`:
query first (the common, cheap path), then a **cloned** body read
(`state ?? RelayState`) when the query param is absent and the request
is a form-encoded POST. The clone is essential — the method handler
downstream still needs an unconsumed body to read `code` /
`SAMLResponse`. Any body-parse failure degrades to "no state",
identical to the pre-existing missing-query behaviour. This is a
general fix (it unblocks true OAuth `form_post` too), not
SAML-specific.

### Why a global state key

The `state` MAC has to verify **before** tenant config is loaded — that's
how recovery works at all. Tenant-scoped keys would create a bootstrap
problem. The global key MACs only `{ tenantId, flowId, nonce, kid }`;
**nothing sensitive lives in the envelope**. Everything else
(`clientPkce`, `appRedirectUri`, scopes, audience, etc.) is in the
server-side `FlowRecord`.

### Two PKCEs, never confuse them

- **`clientPkce`** is the **relying-party → IdP** PKCE. RP generates the
  verifier, sends the challenge to `/authorize`. Stored in
  `FlowRecord.clientPkce`; verified at `/token`.
- The **IdP → upstream provider** PKCE (when we act as a client of
  Google / GitHub / etc.) lives inside `FlowRecord.methodState` for the
  upstream-OAuth methods. The framework never inspects it; it's opaque
  per method.

## Flow-record lifecycle

`FlowRecord` is consumed **exactly once** by the framework, before the
method's callback handler runs. After consume, the in-memory record is
the source of truth for the rest of the request; the framework does
**not** call `consumeFlow` a second time.

1. **Create** — at `/authorize`, after schema validation and after
   `resolveTenant` succeeds. The framework atomically calls
   `SessionStore.saveFlow(flowId, payload, ttl)` with all RP-side fields
   populated and `methodState: null`. The MACed `state` envelope is
   minted from `{ tenantId, flowId, nonce, kid }`. `callbackPath` is
   computed at this point.
2. **Update** — when a method returns
   `{ kind: "challenge", saveMethodState }`, the framework calls
   `SessionStore.updateFlowMethodState(flowId, methodState)` and waits
   for it to resolve **before** sending the redirect response. The user
   agent never sees the upstream redirect until the upstream PKCE
   verifier / nonce / state is durably saved.
3. **Consume** — on the upstream callback, after MAC verification, the
   framework calls `SessionStore.consumeFlow(flowId)`. Atomic
   delete-on-read; concurrent calls resolve to one winner. The returned
   `FlowRecord` is held in memory for the rest of the request.
4. **Snapshot + dispose** — on `MethodResult.success`, the framework
   snapshots the fields needed at `/token` into the auth-code payload
   via `TokenStore.saveCode`. `methodState` is **not** snapshotted; it
   served its callback purpose.

Methods may not call `SessionStore` directly to mutate the flow record.
They observe via `MethodContext.flow` / `MethodContext.methodState` and
request updates via `MethodResult.challenge.saveMethodState`.

## `methodScratch` — cross-flow per-instance state

`methodState` is per-flow and disposed when the flow consumes. Some
methods need state that **outlives** any single flow — e.g. a SAML SP
remembering recently-seen assertion IDs for replay protection across
unrelated logins. For that, `MethodContext` exposes:

```
methodScratch: {
  put(key, value, ttlMs): Promise<Result<void>>
  get(key):               Promise<Result<string>>
  delete(key):            Promise<Result<void>>
}
```

Scope is always `(tenantId, methodId)` — the framework rewrites
user-supplied keys to `scratch:<tenantId>:<methodId>:<userKey>` before
delegating to `SessionStore.{saveScratch,readScratch,deleteScratch}`.
Two method instances cannot observe each other's keys even on a shared
store; the dispatch-shim test in
`test/domain/method-scratch.test.ts` covers this.

Use this sparingly. Most methods need only `methodState`. The cases
that justify scratch are exactly: cross-flow deduplication / replay
state, and per-instance configuration caches the method wants to own
rather than read from `MethodConfig` each request. Anything else
belongs in `methodState` or in a port.

`saveScratch` / `readScratch` / `deleteScratch` are **optional** on
`SessionStore`. Adapters that don't implement them cause every
`methodScratch.*` call to fail with `internal_error` naming the missing
operation — methods surface this in `MethodResult.error`. Memory **and
all four production adapters** (Postgres, D1, DynamoDB, Durable Object)
implement the trio, each opted into the `supportsScratch` conformance
cases.

## `publicRoutes` — anonymous per-instance documents

`/m/<methodId>/*` is normally gated on the framework-set `idp.flow`
cookie: every request must belong to an in-flight authorization. A few
method routes are inherently **public** — a SAML SP must publish its
metadata XML at a stable URL an enterprise IdP admin fetches with no
session. For that, `AuthMethod` exposes an opt-in allowlist:

```
publicRoutes?: ReadonlyArray<string>   // e.g. ["GET /metadata"]
```

A route key listed here is dispatched through `handlePublicMethodRoute`
(`domain/method-route.ts`): no cookie, `ctx.flow === null`,
`ctx.methodState === null`. The handler must be a pure function of
`ctx.tenant` + `ctx.dispatch` + captured config. **Fail-closed:** the
gate opens _only_ for a route key the method explicitly enumerates;
absent (every method's default) the behaviour is unchanged, and the
domain function re-checks membership rather than trusting the HTTP
caller. A flowless route returning `success` is a programming error
(no flow to consume into an auth code) and surfaces as `internal_error`
rather than authenticating.

This is the third framework change SAML drove — after `methodScratch`
and `handleCallback` POST-body state recovery — and like both it is a
**general** capability, not SAML-specific surface (any method may
declare public routes).

## `unsolicitedCallback` — flowless inbound authentication

The normal callback (`/cb/<methodId>`) recovers a MAC-signed state
envelope and `consumeFlow`s a pre-existing flow. SAML IdP-initiated
SSO has neither: the IdP posts an unsolicited signed assertion with no
prior AuthnRequest. `AuthMethod.unsolicitedCallback?: boolean` opts a
method instance into handling that. When set, `handleCallback`, on
finding **no verifiable state envelope** (none present, or a value —
e.g. an IdP `RelayState` deep-link token — that fails MAC
verification), dispatches `GET /callback` with `flow === null` and a
derived `dispatch` (issuer/ACS) instead of erroring. The method
verifies the assertion (signature/issuer/audience/conditions still
fully enforced; `InResponseTo` relaxed to `ifPresent` since none
exists; explicit assertion-ID replay dedup via `methodScratch`) and
returns `success` **with `unsolicitedBinding`** — the operator-
configured `{clientId, redirectUri, scopes}`.

Key points:

- **No `FlowRecord` is synthesized.** `saveEncryptedCode` takes an
  in-memory `CodePayload`; the framework builds one from
  `unsolicitedBinding` + the verified subject and mints a code
  directly. Simpler than the original "synthesize a flow" framing.
- **`unsolicitedBinding` is a minimal optional field on the existing
  `success` variant**, not a new `MethodResult` kind — AD3's "no new
  variant" holds while AD7's IdP-init carve-out is satisfied. It is
  consulted _only_ when `flow === null`; on the normal path a flow
  exists and it is ignored. Flowless `success` without it is a
  programming error (no RP request to bind to) → `internal_error`.
- **`RelayState` ≠ state envelope.** A SAML IdP-init POST may carry a
  `RelayState`; "RelayState present" does not mean "framework envelope
  present". The envelope is real only if it MAC-verifies, so the
  IdP-init path is attempted whenever there is no _verifiable_
  envelope — not merely when state is absent. `RelayState` is never
  interpreted as a redirect target (open-redirect guard); the redirect
  is the config-validated `defaultRedirectUri`.
- **Conservative default preserved.** Absent `unsolicitedCallback`
  (every other method, and SAML instances with no `idpInitiated`
  config), a stateless callback stays `invalid_request` exactly as
  before — byte-identical, fail-closed.

This is the fourth general framework change SAML drove (after
`methodScratch`, POST-body state recovery, and `publicRoutes`);
likewise method-agnostic — any method that can authenticate from an
unsolicited inbound POST may opt in.

## `onLogout` + `challenge.logout` — host-collaborative upstream logout

The library terminates a session by revoking the subject's refresh
tokens (`revokeAllForSubject`, the same primitive `/end_session`
uses). But for an **upstream** logout — a SAML front-channel
`LogoutRequest` arriving at the SP's SLS endpoint — the library hits
two deliberate boundaries: a public route's domain context has no
`tokenStore`, and the library has **no map from an upstream identifier
(SAML `NameID`) to an OIDC `subject`** — that mapping lives in the
host's `success` callback (the host owns the final `SubjectClaim`).

So upstream logout is split the same way `success` is: the method does
**protocol only** (verify the signed `LogoutRequest` via node-saml —
no hand-rolled XML-DSig; build the signed `LogoutResponse`) and returns
`MethodResult.challenge` with an optional **`logout: { nameId?,
sessionIndex? }`** field. The privileged side effect runs in the
framework's public-route pipeline, which fires the new general
`IdPOptions.onLogout(input) → { revokeSubject? } | void` hook; if the
host names a subject, the framework runs `revokeAllForSubject` for it,
then returns the `LogoutResponse`.

Key points:

- **`logout` is a minimal optional field on the existing `challenge`
  variant**, not a new `MethodResult` kind — same shape as Phase 2's
  `success.unsolicitedBinding` (V′). It is consulted **only** on a
  _public_ (flowless) route; an authenticated flow-bearing method
  route never logs anyone out, so the field is inert there.
- **Fail-closed.** A throwing `onLogout`, or a failed
  `revokeAllForSubject`, withholds the `LogoutResponse` (returns
  `internal_error`/the revoke error) rather than telling the IdP the
  user is logged out when they may not be.
- **Method stays port-free.** The method never imports
  `ports/`/`http/`; the framework owns the `tokenStore` + hook. This
  preserves the same invariant every other method obeys.
- **Audit.** Always emits `session_logout` with `via: "upstream_slo"`
  - `methodId`/`methodKind` (and `subjectId` only when one was
    revoked). `via` is general — OIDC RP-Initiated Logout is
    `rp_initiated` (the default), and a future OIDC back-channel logout
    reuses `upstream_slo`.
- **Conservative default preserved.** Absent `onLogout`, the library
  still verifies + acknowledges the logout and audits it, but revokes
  nothing (it cannot resolve the upstream id without the host).

This is the fifth general framework change SAML drove (after
`methodScratch`, POST-body state recovery, `publicRoutes`, and
`unsolicitedCallback`); likewise method-agnostic — any federation
method that can verify an upstream logout signal may use it.

## Response sanitization

Returning an arbitrary `Response` from a method would let it stuff
`Set-Cookie` headers in and bypass framework-owned cookie policy. To
prevent that, the HTTP layer strips a fixed allowlist-violating set of
headers from every method-returned `Response` (logging a programmer-bug
warning via `console.warn`; will switch to the Logger port when that
lands in Phase 8), then merges in `SetCookie[]` data through the
framework's own serializer:

**Stripped:**

- `Set-Cookie`, `Set-Cookie2`
- `Strict-Transport-Security`, `Content-Security-Policy`,
  `Content-Security-Policy-Report-Only`
- `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`
- `Cache-Control` (methods opt in via the typed `cache?: CachePolicy`
  field on `MethodResult.challenge`).

**Cookies applied from `SetCookie[]`** through the framework's
serializer, which enforces:

- `Secure` forced on in production.
- `SameSite` defaulted to `Lax`.
- `HttpOnly` defaulted to `true` for any cookie name matching `auth.*` /
  `idp.*` (the framework's reserved namespace).
- Cookie domain and path defaults from `IdPOptions`.

CI lint additionally flags methods that import `cookie` /
`set-cookie-parser` directly.

## `providerSubject` vs final subject — who creates what

- The **method's `success` result** carries `providerSubject` (upstream
  system's stable identifier — Google's `sub`, GitHub's `id`, the
  password row's `user_id`, the passkey's credential-bound user handle)
  and `properties` (typed claims emitted by the method). The method
  never constructs the final subject identity the IdP issues.
- The **user-supplied `IdPOptions.success` callback** (REQUIRED) maps
  `(tenant, methodId, methodKind, providerSubject, properties, context)
→ SubjectClaim`. This is where the user looks up or creates a stable
  internal user record, decides what subject type to issue (`"user"` vs
  `"admin"` vs `"system"`), and returns the typed claim that becomes the
  JWT subject.
- `IdPOptions.hooks.onSuccess` (optional) is for **observation only** —
  audit, analytics, side effects. Does not influence the issued
  subject; runs after the claim is built.

## TTLs — distinct lifetimes, not interchangeable

- **Flow record TTL** — default **10 minutes**. Pre-callback span:
  upstream login, MFA, consent, mobile app switching. 60 s is far too
  short and will cause user-visible failures.
- **Auth-code TTL** — default **60 seconds**. Post-callback span: RP
  exchanges the code at `/token`. Per OAuth 2.1 BCP, must be very short.
  The framework refuses `saveCode` with `ttl > 60`.
- **Flow cookie TTL** — matches flow record TTL (10 min). Defense in
  depth for the `flow-id-in-uri` recovery path; HttpOnly / Secure /
  SameSite=Lax.
- **Access token TTL** — default 15 minutes.
- **Refresh token TTL** — default 30 days, sliding. Reuse window 60 s.
- **State-MAC key overlap** — at least the flow-record TTL; recommended
  1 hour.

## `ClientConfig` is a discriminated union

`ClientConfig` is `PublicClientConfig | ConfidentialClientConfig`. Hosts
constructing client rows in their `ConfigStore` implementation must
choose a branch at the type level:

- **Public clients**: `pkceRequired: true` is a literal (not a boolean).
  The framework rejects any attempt to disable PKCE for public clients
  at the type level; the runtime check in `domain/authorize.ts` is a
  defensive backstop.
- **Confidential clients**: `secretHash` is required (was optional
  pre-Phase-8). All confidential-client endpoints — `/token`,
  `/revoke`, `/introspect` — validate the presented `client_secret`
  against this hash.

Migration: hosts that ran on pre-Phase-8 `ClientConfig` will see
type errors at compile time wherever they constructed `{type: "public",
pkceRequired: false}` or `{type: "confidential"}` without `secretHash`.
No runtime breakage — both shapes were already rejected at request time.

## Client auth on `/revoke` and `/introspect`

- **`/revoke` (RFC 7009 §2.1 + §2.2):** anonymous calls are permitted
  for tokens issued to **public clients only**. Confidential-client
  tokens require valid `client_id` + `client_secret` (Basic auth or
  form body). Wrong-client revoke returns `invalid_grant` without
  consuming the token; unknown / expired / consumed tokens still 200
  per §2.2.
- **`/introspect` (RFC 7662 §2.1 + §2.2):** client auth is REQUIRED.
  Anonymous calls are rejected at the HTTP layer with `invalid_client`.
  The authenticating client must match the token's `aud` claim; any
  cross-client introspection attempt returns `{active: false}` rather
  than a structured error (§2.2 — don't leak existence of other clients'
  tokens).
- **Refresh-token grant (RFC 6749 §6):** confidential clients MUST
  authenticate. The library now peeks the refresh token before consuming
  so auth failures don't burn the token.

The shared parsing + verification lives in `domain/client-auth.ts`.

## Reuse detection scope

Refresh-token reuse detection lives inside the `TokenStore.consumeRefresh`
adapter: when a token is re-presented inside the reuse window the
adapter returns `invalid_grant` with a typed `reuseSignal` and atomically
revokes **only the affected family**. Family scope matches OAuth 2.0
Security BCP §4.13.2 — escalating further would also revoke legitimate
sibling-device sessions that share the subject (laptop, phone, tablet),
which is a poor default.

Hosts that want to expose "log me out of all devices" UX can call
`revokeAllForSubject(tenantId, subjectId, deps)` — the framework
primitive that wraps `TokenStore.revokeBySubject` with the matching
`token_revoked` audit event (`reason: "subject_revoke"`). It is opt-in
host-driven, never invoked automatically.

## Port consistency contracts

See `ports/CONSISTENCY.md` for the authoritative table. Summary:

- `TokenStore.{saveCode, consumeCode, saveRefresh, consumeRefresh}` —
  **strong, atomic.** Cloudflare KV is **not** acceptable.
- `SessionStore.{saveFlow, updateFlowMethodState, consumeFlow}` — same.
  `consumeFlow` is atomic delete-on-read and **returns the full
  `FlowRecord`** so the framework can snapshot fields before disposal.
- `ConfigStore.getTenantConfig` / `MethodStore.getMethodConfig` —
  **eventual + bounded staleness (TTL ≤ 60 s).** Cache aggressively;
  invalidation hook fires on update.
- `KeyStore.currentSigningKey` — strong. `signingKeys()` (JWKS) —
  eventual OK.
- `AuditLog.log` — append-only, durable. Ordering across instances not
  required.

## Embedding pattern — what the framework does and doesn't do

This package is a **server-side library** that runs inside a larger host
application — the host is the product, this library is the auth brain.
The boundary matters for every scoping decision: features that look like
"identity" sometimes belong on the host side, not in the library.

**The host application owns:**

- The console UI for managing partitions, registered applications, audit
  log display, invite flows, billing.
- The product's data model — Users, Workspaces, Apps, App-Tenants, and
  whatever other concepts the product introduces.
- Authorization (RBAC) — "is this subject allowed to do X?" — including
  whether a subject is an "admin." The library only authenticates; the host
  decides what an authenticated subject is permitted to do.
- Mutations to per-partition config — the host writes through the
  framework's `ConfigStore` / `MethodStore` adapters via plain function
  calls, no HTTP API in between.
- Inheritance logic — e.g. an App's default providers overridden by an
  App-Tenant's own providers. The framework only sees the resolved
  `TenantConfig`; the merge happens in the host's `ConfigStore`
  implementation.

**The library owns:**

- OAuth 2.1 / OIDC Core endpoints (`/authorize`, `/token`, `/cb/*`,
  `/m/*`, `/userinfo`, `/revoke`, `/introspect`, `/.well-known/*`).
- Per-partition isolation — tokens minted for partition A cannot be
  consumed at partition B's `/token`; refresh-token rotation honours
  family scoping; audit events carry the partition id.
- The auth-method registry (factories) and per-partition instance cache.
- Port interfaces (`ConfigStore`, `MethodStore`, `TokenStore`,
  `SessionStore`, `KeyStore`, `AuditLog`) and concrete adapters (memory,
  Postgres, D1, Durable Objects, KV, DynamoDB, KMS).
- Standards posture — PKCE enforcement, refresh-token reuse detection,
  encryption-at-rest of code payloads, MAC-bound state envelope.

### `Tenant` is an opaque partition key

The framework's `Tenant` is **not** a business-domain concept. It is a
configuration partition: an opaque branded string keying the per-request
config blob the framework operates on. The host's `resolveTenant(req)`
decides what counts as a partition for an incoming request; the host's
`ConfigStore` returns the partition's config.

What the framework explicitly does **not** know:

- What a tenant "is" in the host's business model (it could be an
  organization, a workspace, an App-Tenant tuple, a deployment, a
  realm — the framework is agnostic).
- A hierarchy. Tenants are flat. The host may simulate hierarchy by
  encoding tuples into the key.
- Lifecycle. The host creates / destroys partitions on its own schedule.

### Common two-level encoding: `App × App-Tenant`

When the host has two levels of scoping (a registered Application has
default providers, and that App's customers — "App-Tenants" — may override
with their own providers), the standard pattern is:

```ts
// Host's resolveTenant:
async function resolveTenant(req: Request): Promise<Result<TenantId>> {
  const url = new URL(req.url)
  const clientId = url.searchParams.get("client_id")
  const subdomain = url.hostname.split(".")[0]

  const app = await db.apps.findByOAuthClientId(clientId)
  if (!app) return err(authError.tenantNotFound("unknown client", ""))

  const appTenant = await db.appTenants.findBySubdomain(subdomain)

  return ok(`${app.id}:${appTenant?.id ?? "__default__"}` as TenantId)
}

// Host's ConfigStore.getTenantConfig:
async function getTenantConfig(id: TenantId): Promise<Result<TenantConfig>> {
  const [appId, subId] = (id as string).split(":")
  const app = await db.apps.get(appId)
  const appTenant =
    subId === "__default__" ? null : await db.appTenants.get(subId)

  return ok({
    id,
    displayName: appTenant?.displayName ?? app.name,
    clients: [
      {
        id: app.oauthClientId,
        name: app.name,
        type: "confidential",
        secretHash: app.oauthClientSecretHash,
        redirectUris: app.allowedRedirectUris,
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: app.allowedScopes,
        pkceRequired: true,
      },
    ],
    methods: appTenant?.providers ?? app.defaultProviders,
    theme: app.theme,
    cookieDomain: app.cookieDomain,
  })
}
```

The framework gets a single `TenantConfig`; the merge is the host's
business. Tokens minted under `acme:bigcorp` are invalid at
`acme:smallco`, the audit log slices by `tid`, and method-instance caches
are keyed by `(tenantId, methodId)` so the upstream Google client_id for
BigCorp doesn't leak into SmallCo's flow.

### Why the library doesn't ship a console

Open Question #1 in the plan ("Console placement") is closed with **"not in
this package."** The console UI, admin API, invite flow, and audit viewer
are host-application concerns:

- **Console UI** lives in the host product where the rest of the product UI
  lives.
- **Admin API** is unnecessary as a separate HTTP surface — the host
  process imports `createIdP` and the port adapters, so it has direct
  in-process access to every mutation it needs. There is no boundary to
  protect with `/admin/*` routes because there is no other client.
- **RBAC / admin determination** is authorization, not authentication.
  The library authenticates the subject and issues a token; the host's
  middleware reads the token claim, looks the user up in its model, and
  decides what they can do.
- **Audit log display** is read-side; the host queries its underlying
  store directly. Adding a generic `AuditLog.query(filter)` port would be
  necessarily less expressive than raw SQL / native queries the host
  already needs for joins, aggregations, and full-text search.

## Phase status

| Phase                                | Status      | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 — Domain types + project skeleton  | **done**    | All `types/` and `ports/` files populated; `ports/CONSISTENCY.md` written; `createIdP` stub throws.                                                                                                                                                                                                                                                                                                                                                                                                         |
| 2 — Domain logic + memory adapters   | **done**    | Pure functions over typed ports; in-memory adapter set; full unit suite.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 3 — HTTP adapter (Hono)              | **done**    | Thin Hono layer; tenant middleware; Zod schemas; 17-case hand-built OAuth 2.1 / OIDC conformance matrix green.                                                                                                                                                                                                                                                                                                                                                                                              |
| 4 — Credential + WebAuthn methods    | **done**    | `password` (argon2id), `code`, `m2m`, `passkey` on the new `AuthMethod` interface.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 5 — OAuth / OIDC provider family     | **done**    | 15 OAuth/OIDC providers via `buildOauth2Method` / `buildOidcMethod`; matrix test covers each end-to-end.                                                                                                                                                                                                                                                                                                                                                                                                    |
| 6 — Real storage adapters            | **done**    | Postgres, D1, Durable Objects, KV (read-eventual paths), DynamoDB, KMS; parameterized port-conformance suite under `test/ports/`.                                                                                                                                                                                                                                                                                                                                                                           |
| 7 — Library-only scoping             | **done**    | Phase 7 rescoped from "build a console" to "make the embedding contract explicit." See "Embedding pattern" above. Open Question #1 closed.                                                                                                                                                                                                                                                                                                                                                                  |
| 8 — Standards + production hardening | in progress | Session 1: PKCE type-system enforcement, RFC 7009 revoke + RFC 7662 introspect client-auth + audience checks, refresh-grant RFC 6749 §6 client-auth, new `TokenStore.peekRefresh` port. Session 2 (OIDC issuance, RFC 9126 PAR, RFC 9449 DPoP, RFC 7591 DCR, OIDC RP-Initiated Logout 1.0, OIDC Core `claims` parameter + pairwise subjects + scope-gated profile claims, discovery metadata fill-in). 480/480 tests, both tsconfigs clean. Remaining: mTLS hook, rate-limiter port, Logger / Tracer ports. |

## OIDC issuance (Session 2)

### `id_token` minting

`/token` issues an OIDC `id_token` whenever the granted scope set
includes `openid` AND the grant carries an end-user `auth_time`
(authorization_code and refresh_token grants — `client_credentials`
never issues one). The token carries:

- `iss`, `sub`, `aud = client_id`, `exp`, `iat` (REQUIRED — OIDC Core §2)
- `auth_time` — stamped at `MethodResult.success`; **stable** across
  refresh-grant rotations per §12.
- `nonce` — echoed verbatim from the `/authorize` request when present
  (§3.1.2.1). **NOT** carried forward on refresh.
- `at_hash` — left-half SHA-256 of the issued access token, base64url
  (§3.1.3.6).
- `amr` — derived from the originating `methodKind` via a small RFC 8176
  mapping table (`password→["pwd"]`, `code→["otp"]`, `passkey→["hwk"]`).
  Federated providers omit `amr` because no standardized AMR value
  cleanly maps; hosts wanting richer semantics use the claims hook.
- §5.1 profile claims gated by granted scopes (§5.4 mapping). Both the
  id_token and `/userinfo` share `pickScopedClaims` so the surfaces
  agree on what each scope grants.
- Host-supplied vendor mappings via `IdPOptions.customScopeClaims` are
  merged on top of §5.4 at scope-gating time. Standard names always
  win on collision (`email` cannot be silently redefined); the union
  of host-supplied keys + claim-names is reflected in discovery's
  `scopes_supported` / `claims_supported`. id_token bakes the resolved
  claims at mint; `/userinfo` reads `customScopeClaims` live so
  config-driven vocabulary changes take effect on the next request
  without re-issuing tokens.

OIDC Core §5.5 `claims` parameter is parsed at `/authorize`, stored on
`FlowRecord.claimsRequest`, snapshotted into `CodePayload.claimsRequest`
and `RefreshTokenPayload.claimsRequest`. The names from `claims.id_token`
are passed as an extra set into the id-token assembler, bypassing scope
gating. The names from `claims.userinfo` are embedded into the access
token's `uic` claim so the resource server can apply the same bypass
without re-resolving the original `/authorize` request.

### Pairwise subjects (§8.1)

When a `ClientConfig.sectorIdentifier` is set, `deriveSubjectId` mixes
it into the hash seed:

```
sub = base64url(sha256(`${sectorIdentifier}\0${claim.type}\0${ordered}`))[:22]
```

Two clients sharing the same `sectorIdentifier` see the same `sub` for
the same end user; different values yield different `sub`s. Absent =
public subject (identical across all RPs). Discovery advertises
`subject_types_supported = ["public", "pairwise"]` unconditionally.

### `/end_session` (RP-Initiated Logout 1.0)

The handler validates the optional `id_token_hint` against the IdP's
own signing keys with `acceptExpired: true` (spec §2 — logout commonly
follows token expiry). It cross-checks the `client_id` parameter
matches the hint's `aud` if both are present, validates
`post_logout_redirect_uri` against the resolved client's
`postLogoutRedirectUris` list (exact match — never substring or
prefix, to defeat open-redirector misuse), revokes the identified
subject's refresh tokens via `revokeAllForSubject`, emits a
`session_logout` audit event, and either redirects with `state`
echoed or returns a 200 plain-text "Logged out" page when no URI was
supplied.

### Pushed Authorization Requests (RFC 9126)

`POST /par` accepts the standard `/authorize` parameter set in a form
body plus client auth. The framework persists the request under an
opaque `urn:ietf:params:oauth:request_uri:<...>` via
`SessionStore.savePar` (default TTL 60 s), and `/authorize?request_uri=...`
rehydrates the parameter record through the same Zod parser the direct
path uses. The user-agent URL after PAR carries only `client_id` and
`request_uri` — any extra parameters are ignored (§4). Per-client
`ClientConfig.requirePushedAuthorizationRequests` refuses a direct
`/authorize` (no `request_uri`) with `invalid_request`.

### DPoP — sender-constrained access tokens (RFC 9449)

The RP/client generates an asymmetric keypair, signs a fresh proof JWT
per request (`DPoP:` header), and the IdP binds the issued access
token's `cnf.jkt` to the RFC 7638 thumbprint of the embedded public
JWK. Refresh tokens carry `RefreshTokenPayload.dpopJkt` so rotation
re-enforces sender constraint — the refresh handler checks the binding
**before** consuming, so a no-proof attempt does not burn the token.

`/token` and `/userinfo` accept DPoP-bound tokens (`Authorization:
DPoP <token>` at the RS, plus a fresh proof whose `ath` equals
SHA-256(access_token)). Per-client `dpopRequired` refuses bearer-only
requests before any token is minted. Replay protection lives in
`TokenStore.recordDpopJti`; a re-presentation within the TTL window
returns `invalid_dpop_proof` with a typed `replaySignal` and emits a
`dpop_replay_detected` audit event.

Discovery advertises
`dpop_signing_alg_values_supported = ["ES256", "EdDSA"]`. Symmetric
algs and `alg: "none"` are rejected at parse time.

### Dynamic Client Registration (RFC 7591)

`POST /register` accepts a JSON request body, validates structure
(redirect_uris present + absolute URIs, recognized
`token_endpoint_auth_method`), and defers persistence to the
`IdPOptions.registerClient` host hook. The framework mints a
`client_id` (and `client_secret` for confidential clients) and offers
both to the host, which writes through its own `ConfigStore` and
returns the final `ClientConfig`. Response is HTTP 201 per §3.2.1
with `client_secret_expires_at: 0`. When the hook is not configured,
the endpoint returns `invalid_request: "dynamic client registration
is not enabled on this deployment"` so RPs get a clear signal rather
than a 404.
