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
handler functions**, not a framework module — it imports only Web Fetch
`Request` / `Response` and the types in `src/types/`. The HTTP adapter
mounts each tenant's configured methods under
`/<MethodConfig.id>/*` (the tenant-local instance id, not the factory
kind).

## Type system — what lives where

| File                     | Purpose                                                                                                                            |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `types/result.ts`        | `Result<T, E>` + `ok` / `err` / `isOk` / `isErr` helpers. The domain returns these instead of throwing.                            |
| `types/error.ts`         | `AuthError` closed taxonomy + `authError.*` constructor helpers. Maps 1:1 to OAuth 2.0 codes plus framework-internal codes.        |
| `types/tenant.ts`        | `TenantId` brand, `TenantConfig`, `ClientConfig`, `MethodConfig`, `MethodType`, `TenantContext`, `TenantRecovery`, `StateKeyRing`. |
| `types/flow.ts`          | `FlowRecord` — single source of truth for in-flight authorization state.                                                           |
| `types/method.ts`        | `AuthMethod`, `AuthMethodFactory`, `MethodContext`, `MethodResult`, `SetCookie`, `CachePolicy`. **Zero framework imports.**        |
| `types/authorization.ts` | `AuthorizationRequest`, `AuthorizationState`.                                                                                      |
| `types/token.ts`         | `CodePayload`, `AccessTokenClaims`, `RefreshTokenPayload`, `TokenResponse`.                                                        |
| `types/subject.ts`       | `SubjectSchema`, `SubjectPayload`, `SubjectClaim`. Library-agnostic via Standard Schema v1; Zod recommended (AD4).                 |
| `types/idp.ts`           | Public surface: `IdPOptions`, `IdP`, `SuccessMapInput`, `SuccessEvent`, `FailureEvent`, `PersistUpstreamTokens`.                   |
| `ports/*.ts`             | Port interfaces. Each carries consistency JSDoc; the canonical contract table is in `ports/CONSISTENCY.md`.                        |

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

## Response sanitization

Returning an arbitrary `Response` from a method would let it stuff
`Set-Cookie` headers in and bypass framework-owned cookie policy. To
prevent that, the HTTP layer strips a fixed allowlist-violating set of
headers from every method-returned `Response` (logging a programmer-bug
warning at ERROR level), then merges in `SetCookie[]` data through the
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
  const appTenant = subId === "__default__" ? null : await db.appTenants.get(subId)

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

| Phase                                | Status         | Notes                                                                                                                                                                          |
| ------------------------------------ | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1 — Domain types + project skeleton  | **done**       | All `types/` and `ports/` files populated; `ports/CONSISTENCY.md` written; `createIdP` stub throws.                                                                            |
| 2 — Domain logic + memory adapters   | **done**       | Pure functions over typed ports; in-memory adapter set; full unit suite.                                                                                                       |
| 3 — HTTP adapter (Hono)              | **done**       | Thin Hono layer; tenant middleware; Zod schemas; 17-case hand-built OAuth 2.1 / OIDC conformance matrix green.                                                                 |
| 4 — Credential + WebAuthn methods    | **done**       | `password` (argon2id), `code`, `m2m`, `passkey` on the new `AuthMethod` interface.                                                                                             |
| 5 — OAuth / OIDC provider family     | **done**       | 15 OAuth/OIDC providers via `buildOauth2Method` / `buildOidcMethod`; matrix test covers each end-to-end.                                                                       |
| 6 — Real storage adapters            | **done**       | Postgres, D1, Durable Objects, KV (read-eventual paths), DynamoDB, KMS; parameterized port-conformance suite under `test/ports/`.                                              |
| 7 — Library-only scoping             | **done**       | Phase 7 rescoped from "build a console" to "make the embedding contract explicit." See "Embedding pattern" above. Open Question #1 closed.                                     |
| 8 — Standards + production hardening | in progress    | Session 1 shipped: PKCE type-system enforcement, RFC 7009 revoke + RFC 7662 introspect client-auth + audience checks, refresh-grant RFC 6749 §6 client-auth, new `TokenStore.peekRefresh` port, 27/27 conformance cases. Remaining: DPoP, PAR, mTLS hook, DCR helper, rate-limiter port, Logger/Tracer ports. |
