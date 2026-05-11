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

## Phase status

| Phase                                | Status   | Notes                                                                                                                                  |
| ------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 1 — Domain types + project skeleton  | **done** | All `types/` and `ports/` files populated; `ports/CONSISTENCY.md` written; `createIdP` stub throws.                                    |
| 2 — Domain logic + memory adapters   | pending  | Pure functions over typed ports; in-memory adapter set; full unit suite.                                                               |
| 3 — HTTP adapter (Hono)              | pending  | Thin Hono layer; tenant middleware; Zod schemas; hand-built conformance matrix gate (17 cases minimum, see plan §"Conformance scope"). |
| 4 — Credential + WebAuthn methods    | pending  | `password`, `code`, `m2m`, `passkey` on the new `AuthMethod` interface.                                                                |
| 5 — OAuth / OIDC provider family     | pending  | All 22 existing providers ported to `oauth2-generic` / `oidc-generic`.                                                                 |
| 6 — Real storage adapters            | pending  | D1, Durable Objects, KV (read-eventual paths only), DynamoDB, Postgres, KMS.                                                           |
| 7 — Management console               | pending  | `apps/console/` — IdP authenticates its own admin login.                                                                               |
| 8 — Standards + production hardening | pending  | PKCE enforcement, revoke, introspect, DPoP, PAR, mTLS, DCR, rate limiting, OTEL.                                                       |
