# Multi-Tenant IdP — Architectural Rebuild Plan

**Status:** Draft v1
**Owner:** Matt Puccio
**Target:** Replace the current OpenAuth implementation with a cleaner architecture before any production usage.
**Backward compatibility:** None required. Existing tags `0.6.x`-`0.8.1` remain available; new work proceeds in parallel and replaces.

---

## TL;DR

The current OpenAuth code has three structural mistakes that this rebuild eliminates:

1. **Tenancy is a URL concept** (`/tenant/:tenantId/*`) instead of a request-resolution function.
2. **Provider abstraction is coupled to Hono** (`Provider.init(route, opts)` forces per-request Hono construction when configs are dynamic).
3. **One fat `issuer({})` config object** instead of composable primitives.

We replace these with:

1. **Tenant resolved per request** by a user-supplied function. No tenant in the URL.
2. **`AuthMethod` as data + handler functions**, not Hono modules. Framework-agnostic, no per-request init.
3. **`createIdP({...ports})` returns a `handle(req)` function**. The user mounts it wherever they want.

The IdP simultaneously serves end-user auth flows for tenant applications AND hosts the management console's own login (the console is just another OAuth client of the IdP).

All 22 existing providers will be ported to the new `AuthMethod` interface in Phase 5.

---

## Goals

- **Cleaner core:** authorize/token/refresh/revoke flows as pure functions over typed ports. Testable without any HTTP framework — domain accepts `Request`, returns `Response` (Web Fetch standards), but never imports Hono or any other framework.
- **Real multi-tenancy:** tenant resolution as a user-defined function. Subdomain, header, JWT claim, mTLS cert — all valid.
- **Zero per-request overhead** for dynamic tenant configs. Per-tenant config caching with TTL + invalidation.
- **Standards-first:** OAuth 2.1 baseline (PKCE required). DPoP, PAR, revocation, introspection in Phase 8.
- **Edge-ready:** works on Cloudflare Workers, Bun, Node, AWS Lambda with the same code.
- **Self-hosting console:** the management console authenticates via the same IdP it manages. Eat the dogfood.

## Non-Goals (for this rebuild)

- SAML support (defer until a customer asks).
- CIBA / device flow (defer).
- LDAP federation (defer).
- ORM / typed query layer (out of scope; raw drivers are fine for KV-shaped workloads).
- UI customization framework (basic theming only; rich customization is later).
- i18n (English first; structure for it).

---

## Glossary

| Term              | Meaning                                                                                                                                                                                                                                                                                         |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **IdP**           | Identity Provider — the running service that handles OAuth/OIDC flows.                                                                                                                                                                                                                          |
| **Tenant**        | A logical isolation boundary (organization, workspace, customer). Each tenant has its own config: clients, auth methods, branding.                                                                                                                                                              |
| **System tenant** | A reserved tenant used by the management console. Has its own admin auth methods.                                                                                                                                                                                                               |
| **Client**        | An OAuth/OIDC client (app, SPA, mobile) registered to a tenant.                                                                                                                                                                                                                                 |
| **AuthMethod**    | A pluggable authentication mechanism (password, passkey, Google OIDC, etc.). Data-shaped — declares routes statically, supplies handler functions.                                                                                                                                              |
| **Subject**       | A successfully authenticated principal (a user, a service). Has a stable ID and typed claims.                                                                                                                                                                                                   |
| **Port**          | An interface the domain depends on (e.g., `TokenStore`).                                                                                                                                                                                                                                        |
| **Adapter**       | A concrete implementation of a port for a specific environment (e.g., `D1TokenStore`, `MemoryTokenStore`).                                                                                                                                                                                      |
| **MethodContext** | Per-request context handed to an `AuthMethod` handler: request, tenant config, parsed cookies (read-only), and current authorization state. Methods do not mutate cookies or issue tokens directly — they return a `MethodResult` describing what should happen, and the HTTP layer applies it. |
| **MethodResult**  | Discriminated union returned by an `AuthMethod` handler: `challenge` (render UI/redirect), `success`, `denied`, or `error`.                                                                                                                                                                     |

---

## Architectural Decisions

These are the big calls that shape everything else. Sign off on these before Phase 1 starts.

| #    | Decision                                                                                       | Choice                                                                                                          | Alternative considered                                    | Why                                                                                                                                                                                                                                                                                                                     |
| ---- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AD1  | Tenant resolution                                                                              | User-supplied `resolveTenant(req)` function                                                                     | URL path (`/tenant/:id/*`)                                | Flexibility (subdomain, header, JWT, mTLS) without coupling tenancy to URLs.                                                                                                                                                                                                                                            |
| AD2  | Provider abstraction                                                                           | `AuthMethod` as data + handler functions                                                                        | Hono-mount-per-provider                                   | Eliminates per-request init cost. Framework-agnostic.                                                                                                                                                                                                                                                                   |
| AD3  | HTTP framework                                                                                 | Hono                                                                                                            | Custom router, Express, native fetch handler              | Already in use. Edge-friendly. Good DX. Adapter layer remains thin so this is swappable.                                                                                                                                                                                                                                |
| AD4  | Schema validation                                                                              | **Zod** (decided)                                                                                               | Valibot, Arktype, Effect Schema                           | Bigger bundle than Valibot but the ecosystem advantage matters: better integrations (tRPC, OpenAPI generators, Hono validators), more community examples, broader team familiarity. Edge bundle cost is acceptable for this codebase. Used for all I/O boundary validation (HTTP schemas) and method-config validation. |
| AD5  | Error handling                                                                                 | `Result<T, E>` + typed errors                                                                                   | Throw + global handler                                    | Explicit error paths. Easier composition.                                                                                                                                                                                                                                                                               |
| AD6  | Crypto                                                                                         | `jose` (panva)                                                                                                  | Web Crypto direct, `oauth4webapi`                         | Already used. Industry standard.                                                                                                                                                                                                                                                                                        |
| AD7  | OAuth primitives — **server side** (IdP issues tokens to its clients)                          | Custom implementation, with a **hand-built conformance matrix** running on every commit from **Phase 3 onward** | `node-oidc-provider`, OIDF Conformance Suite from day one | The server is small (~5 endpoints + JWT) and benefits from edge-friendliness. Hand-built matrix gives fast inner-loop feedback. OIDF Conformance Suite is **explicitly deferred** until an external tenant requires certification — see _Conformance scope_ below.                                                      |
| AD7b | OAuth primitives — **client side** (IdP acts as OAuth client of Google/GitHub/etc. in Phase 5) | `oauth4webapi` (panva)                                                                                          | Custom per-provider                                       | Outgoing flows hit dozens of provider quirks (Apple form_post, MS tenants, PKCE variants). `oauth4webapi` handles these once with strict standards compliance. Pairs naturally with `jose` which we already use.                                                                                                        |
| AD8  | Storage abstraction                                                                            | Separated ports per access pattern                                                                              | Single `StorageAdapter` KV                                | Each port can be backed by the right tech (KMS for keys, KV for sessions, append-log for audit).                                                                                                                                                                                                                        |
| AD9  | Token issuance                                                                                 | JWT access tokens (ES256) + opaque refresh tokens                                                               | All opaque                                                | Standard. Stateless validation for access tokens. Stateful refresh for revocation.                                                                                                                                                                                                                                      |
| AD10 | Sessions for console                                                                           | Same OAuth flow as any client                                                                                   | Server-side session cookie                                | Eat the dogfood. One auth implementation to maintain.                                                                                                                                                                                                                                                                   |
| AD11 | Default key algorithm                                                                          | ES256 (existing) + Ed25519 (new)                                                                                | RS256 only                                                | ES256 is small + fast. Ed25519 for tenants who prefer it.                                                                                                                                                                                                                                                               |
| AD12 | Package layout                                                                                 | **In-place rebuild inside `packages/openauth/src/`** (decided)                                                  | Parallel `packages/idp/`, in-place with feature flag      | No production consumers; no need for parallel safety net. Old files deleted as replacements arrive. Master stays compiling because each PR completes a slice.                                                                                                                                                           |
| AD13 | Effect-TS                                                                                      | Not in scope for v1                                                                                             | Adopt Effect-TS                                           | Steep learning curve. Domain is small enough that plain functions + Result types are fine. Revisit later.                                                                                                                                                                                                               |

**Decisions resolved (pre-Phase 1):**

- ✅ **Package name** stays `@_mustachio/openauth`. Bump to `1.0.0` when the rebuild ships to signal the architectural change.
- ✅ **AD12 — In-place** in `packages/openauth/src/`. No parallel package. Old files deleted as replacements arrive; each PR completes a coherent slice so master compiles throughout.
- ✅ **AD4 — Zod** for schema validation.
- ✅ **AD7 — Hand-built conformance matrix only.** OIDF deferred indefinitely.

**Still open:**

- [ ] **Console placement.** Separate `packages/console/` (Next.js / Astro / SvelteKit) or under `apps/console/`? (Pre-Phase 7.)

---

## Repository Layout

Per AD12 (in-place rebuild). Final structure once Phase 1-8 complete:

**In-place rebuild — same package, new structure.** Files under `packages/openauth/src/` are reorganized as the rebuild progresses. The old `issuer.ts`, `provider/*.ts`, etc. are deleted as their replacements arrive. Each PR is scoped to leave master compiling.

```
packages/
├── openauth/                         # Same package name; rebuild lives here
│   ├── src/
│   │   ├── index.ts                  # Public API: createIdP, types
│   │   │
│   │   ├── types/                    # Phase 1: all domain types live here
│   │   │   ├── tenant.ts             # TenantContext, TenantConfig, ClientConfig
│   │   │   ├── method.ts             # AuthMethod, MethodContext, MethodResult
│   │   │   ├── authorization.ts      # AuthorizationState, AuthorizationRequest
│   │   │   ├── token.ts              # AccessToken, RefreshToken, Code
│   │   │   ├── subject.ts            # Subject, SubjectSchema (Zod-backed, with arktype interop for legacy)
│   │   │   ├── result.ts             # Result<T, E>, ok/err helpers
│   │   │   └── error.ts              # AuthError taxonomy
│   │   │
│   │   ├── ports/                    # Phase 1: interfaces only
│   │   │   ├── config-store.ts       # ConfigStore: tenant lookup
│   │   │   ├── token-store.ts        # TokenStore: codes + refresh tokens
│   │   │   ├── session-store.ts      # SessionStore: flow records (required) + optional long-lived sessions
│   │   │   ├── key-store.ts          # KeyStore: signing/encryption keys
│   │   │   ├── audit-log.ts          # AuditLog: append-only events
│   │   │   └── method-store.ts       # MethodStore: per-tenant auth method config
│   │   │
│   │   ├── domain/                   # Phase 2: pure functions over ports
│   │   │   ├── authorize.ts          # Initiate auth flow, validate request
│   │   │   ├── token.ts              # Issue access + refresh tokens
│   │   │   ├── refresh.ts            # Refresh token rotation
│   │   │   ├── revoke.ts             # Token revocation
│   │   │   ├── introspect.ts         # Token introspection
│   │   │   ├── userinfo.ts           # OIDC userinfo endpoint
│   │   │   ├── discovery.ts          # /.well-known metadata
│   │   │   ├── pkce.ts               # PKCE validation
│   │   │   ├── jwt.ts                # JWT signing/verification (uses jose)
│   │   │   └── crypto.ts             # Encryption helpers
│   │   │
│   │   ├── adapters/                 # Phase 2 + Phase 6
│   │   │   ├── memory/               # Phase 2: in-memory stores for tests + dev
│   │   │   ├── d1/                   # Phase 6: Cloudflare D1
│   │   │   ├── kv/                   # Phase 6: Cloudflare KV
│   │   │   ├── dynamo/               # Phase 6: AWS DynamoDB
│   │   │   ├── postgres/             # Phase 6: Postgres (Node)
│   │   │   └── kms/                  # Phase 6: AWS KMS / Cloudflare DO for keys
│   │   │
│   │   ├── http/                     # Phase 3: HTTP adapter (Hono)
│   │   │   ├── router.ts             # Top-level Hono app
│   │   │   ├── handlers/             # One file per endpoint
│   │   │   │   ├── authorize.ts
│   │   │   │   ├── token.ts
│   │   │   │   ├── userinfo.ts
│   │   │   │   ├── revoke.ts         # Phase 8
│   │   │   │   ├── introspect.ts     # Phase 8
│   │   │   │   ├── par.ts            # Phase 8
│   │   │   │   ├── jwks.ts
│   │   │   │   └── metadata.ts
│   │   │   ├── middleware/
│   │   │   │   ├── tenant.ts         # Resolve tenant + load config
│   │   │   │   ├── audit.ts          # Emit audit events
│   │   │   │   ├── error.ts          # Map AuthError → Response
│   │   │   │   └── cors.ts
│   │   │   └── schemas/              # Zod input schemas per endpoint
│   │   │
│   │   ├── methods/                  # Phase 4-5: AuthMethod implementations
│   │   │   ├── password.ts           # Phase 4
│   │   │   ├── code.ts               # Phase 4 (magic email/SMS code)
│   │   │   ├── m2m.ts                # Phase 4 (client credentials)
│   │   │   ├── passkey.ts            # Phase 4 (WebAuthn)
│   │   │   ├── oauth2-generic.ts     # Phase 5 (base OAuth 2.0 method)
│   │   │   ├── oidc-generic.ts       # Phase 5 (base OIDC method, extends oauth2)
│   │   │   └── providers/            # Phase 5: pre-configured wrappers
│   │   │       ├── google.ts
│   │   │       ├── github.ts
│   │   │       ├── apple.ts
│   │   │       └── ... (one per existing provider)
│   │   │
│   │   ├── ui/                       # Server-rendered JSX (existing pattern stays)
│   │   │   ├── select.tsx            # Provider selection
│   │   │   ├── password-form.tsx
│   │   │   ├── passkey-form.tsx
│   │   │   ├── code-form.tsx
│   │   │   └── theme.ts
│   │   │
│   │   └── util/
│   │       ├── lazy.ts
│   │       └── url.ts
│   │
│   └── test/                         # Phase-aligned test files
│       └── conformance/              # Hand-built OAuth 2.1 + OIDC matrix (Phase 3+)

apps/
└── console/                          # Phase 7: management console
    ├── src/                          # Whatever stack we pick (likely Next.js or Astro)
    └── ...
```

**Files removed during the rebuild** (replaced by the new structure):

- `src/issuer.ts` (~1600 LOC) → split into `src/http/`, `src/domain/`, `src/methods/`
- `src/provider/*.ts` (all 22 files) → `src/methods/*.ts` (per Phase 5 migration matrix)
- `src/storage/*.ts` (current single-port model) → `src/ports/*.ts` + `src/adapters/**`
- `src/ui/*.tsx` → reorganized under `src/ui/` with framework-agnostic helpers

---

## Core Type System (Phase 1 deliverable)

This is the contract that drives everything else. Get it right before writing any logic.

### Result type

```ts
// types/result.ts
export type Result<T, E = AuthError> =
  | { ok: true; value: T }
  | { ok: false; error: E }

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value })
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error })
```

### Error taxonomy

```ts
// types/error.ts
export type AuthError =
  | { code: "invalid_request"; description: string; field?: string }
  | { code: "invalid_client"; description: string }
  | { code: "invalid_grant"; description: string }
  | { code: "unauthorized_client"; description: string }
  | { code: "unsupported_grant_type"; description: string }
  | { code: "invalid_scope"; description: string }
  | { code: "access_denied"; description: string }
  | { code: "unknown_state"; description: string }
  | { code: "server_error"; description: string; cause?: unknown } // RFC 6749 §5.2 — token endpoint server-side failure (hook threw, downstream unavailable, etc.)
  | { code: "tenant_not_found"; description: string; tenantId: string }
  | {
      code: "method_not_found"
      description: string
      methodId?: string
      methodKind?: string
    } // populate whichever was requested
  | { code: "internal_error"; description: string; cause?: unknown } // framework-internal; HTTP layer maps to `server_error` at OAuth endpoints
```

These map 1:1 to OAuth 2.0 error codes plus a few framework-internal ones. HTTP layer maps `AuthError` → `{ status, body }`.

### Tenant

```ts
// types/tenant.ts
export type TenantId = string & { readonly __brand: "TenantId" }

export type TenantConfig = {
  id: TenantId
  displayName: string
  clients: ClientConfig[]
  methods: MethodConfig[]
  theme?: ThemeConfig
  cookieDomain?: string // for cross-subdomain SSO
  refreshTtl?: number // override default
  accessTtl?: number
  // ... other tenant-scoped config
}

export type ClientConfig = {
  id: string
  name: string
  type: "public" | "confidential"
  secretHash?: string // bcrypt or scrypt; null for public
  redirectUris: string[]
  grantTypes: GrantType[]
  scopes: string[]
  pkceRequired: boolean // defaults to true
  dpopRequired?: boolean // Phase 8
}

export type MethodConfig = {
  id: string // TENANT-LOCAL instance id, e.g. "google-workspace", "google-personal"
  kind: string // FACTORY id — selects which AuthMethodFactory builds this instance, e.g. "google", "oidc-generic"
  type: MethodType // discriminator hint for UI/routing; must agree with the factory's type
  enabled: boolean
  config: Record<string, unknown> // method-specific (client_id, scopes, etc.); validated by factory.configSchema
}

// Why separate `id` and `kind`: a tenant can register multiple instances of the same factory.
// Example: one tenant has both a "Google Workspace" SSO ({ kind: "google", id: "google-workspace" })
// and a separate consumer "Google Sign-In" ({ kind: "google", id: "google-personal" }), each with
// its own client_id and configured scopes. The framework dispatches URL routes by `id`; the factory
// is resolved by `kind`.

export type MethodType =
  | "oauth2"
  | "oidc"
  | "password"
  | "code"
  | "m2m"
  | "passkey"
  | "custom"

export type TenantContext = {
  id: TenantId
  config: TenantConfig
  request: {
    raw: Request
    custom: Record<string, unknown> // user's resolveTenant can attach extras
  }
}
```

### Subject (typed user identity)

Reuse the existing subject pattern, but standardize on **Zod** for the canonical schema definition. Optional arktype interop for users migrating from the current code. Defined in `types/subject.ts`.

### AuthMethod — the core abstraction

Methods are **Web-Fetch-shaped, not framework-shaped.** They depend on `Request` and `Response` (Web standards) and on a small `MethodContext` of plain data. They do **not** import from Hono. Cookies are returned as data, applied to the final response by the HTTP layer.

```ts
// types/method.ts
// NO framework imports. Web Fetch standard only.

// P = properties type the method emits to the user's success callback.
// S = method-private state stored in FlowRecord.methodState; opaque to the framework.
export type AuthMethod<P = unknown, S = unknown> = {
  id: string // tenant-local instance id (MethodConfig.id) — populated by factory.build
  kind: string // factory kind (MethodConfig.kind) — populated by factory.build
  type: MethodType
  routes: Record<string, MethodHandler<P, S>> // key = "GET /authorize", "POST /callback", etc.
  client?: ClientFn<P> // for token exchange at /token (if applicable)
}

export type MethodHandler<P, S> = (
  ctx: MethodContext<S>,
) => Promise<MethodResult<P, S>>

// MethodContext does NOT carry raw config — methods capture typed config via closure
// in factory.build. The framework gives them only request-scoped data.
export type MethodContext<S = unknown> = {
  request: Request // Web Fetch standard, not Hono Context
  subPath: string // path within the method's mount, e.g. "/callback"
  tenant: TenantContext
  flow: FlowRecord | null // null if /authorize is being initiated; populated on callback
  methodState: S | null // shortcut to flow?.methodState, typed
  cookies: ReadonlyMap<string, string> // parsed from incoming Request, read-only
}

export type MethodResult<P = unknown, S = unknown> =
  | {
      kind: "challenge"
      response: Response // body + non-policy headers
      setCookies?: SetCookie[] // applied by framework, enforces policy
      saveMethodState?: S // merged into FlowRecord.methodState before response is sent
      cache?: CachePolicy // serialized to Cache-Control by framework
    }
  | {
      kind: "success"
      providerSubject: string
      properties: P
      setCookies?: SetCookie[]
    }
  | { kind: "denied"; reason: string; setCookies?: SetCookie[] }
  | { kind: "error"; error: AuthError }

export type CachePolicy = {
  maxAge?: number // seconds; 0 means no-store (default for auth UI)
  sMaxAge?: number // shared cache TTL (CDN)
  isPrivate?: boolean // Cache-Control: private
  immutable?: boolean // for static assets only
}

export type SetCookie = {
  name: string
  value: string | null // null = clear cookie (sets Max-Age=0)
  maxAge?: number
  path?: string
  domain?: string
  httpOnly?: boolean
  secure?: boolean
  sameSite?: "lax" | "strict" | "none"
}

export type ClientFn<P> = (input: {
  clientID: string
  clientSecret: string
  params: Record<string, string>
}) => Promise<Result<P, AuthError>>

// A factory takes the tenant's per-method config (raw, from ConfigStore) and returns
// a configured AuthMethod. The factory owns config validation via a Zod schema, so the
// boundary between `MethodConfig.config: Record<string, unknown>` and typed method
// internals is checked exactly once, at config-load time per tenant.
export type AuthMethodFactory<P = unknown, S = unknown, Cfg = unknown> = {
  // Factory identifier — matches MethodConfig.kind. Multiple MethodConfig entries
  // may share the same `kind` (multiple Google providers in one tenant, etc.).
  kind: string

  // Zod schema for the tenant-supplied config blob. The framework runs this
  // when ConfigStore returns a tenant's MethodConfig.config and rejects loads
  // that don't validate (audit + log). Methods never see unvalidated input.
  configSchema: z.ZodType<Cfg>

  // Build a method instance from validated config plus the binding context.
  // The factory MUST populate the returned AuthMethod.id with input.id and
  // AuthMethod.kind with input.kind — the framework verifies this and fails the
  // load with audit `factory_id_mismatch` if either is wrong.
  // May be async (e.g., to fetch OIDC discovery doc, JWKS). Cached per
  // (tenantId, MethodConfig.id) with TTL matching ConfigStore. Routes mount at
  // /<MethodConfig.id>/* so two instances of the same factory get distinct paths.
  build: (input: {
    id: string // MethodConfig.id  (tenant-local instance id, becomes AuthMethod.id)
    kind: string // MethodConfig.kind (factory id, becomes AuthMethod.kind)
    tenantId: TenantId
    config: Cfg // validated against configSchema
  }) => Promise<AuthMethod<P, S>>
}
```

**Per-tenant config → typed method config.** The boundary between user-supplied tenant config (`MethodConfig.config: Record<string, unknown>` in `ConfigStore`) and typed method internals is closed by `AuthMethodFactory.configSchema`:

1. `ConfigStore.getTenantConfig(tenantId)` returns the tenant's config, including `methods: MethodConfig[]`.
2. For each `MethodConfig`, the framework looks up the registered `AuthMethodFactory` by `MethodConfig.kind`. If no factory matches that `kind`, this `MethodConfig` is treated as disabled (audit `unknown_method_kind` with the tenant-local `id` so operators can find the bad config row).
3. The framework validates `MethodConfig.config` against `factory.configSchema`. Validation failure → this instance disabled for this tenant, audit `invalid_method_config` with Zod error path. The IdP keeps running with the other methods.
4. The validated config goes into `factory.build({ id: cfg.id, kind: cfg.kind, tenantId, config: validatedCfg })`, producing a fully-typed `AuthMethod<P, S>`. The framework verifies the returned method's `id` and `kind` match the inputs (otherwise: load fails, audit `factory_id_mismatch`). The result is cached per `(tenantId, MethodConfig.id)` in-process; cache TTL matches `ConfigStore` TTL; invalidation hook fires when tenant config changes.
5. The built method's routes are mounted at `/<MethodConfig.id>/*` — the **tenant-local instance id**, not `kind`. Two Google instances (`google-workspace`, `google-personal`) get distinct URL spaces and distinct caches.

This makes the dynamic per-tenant case strictly type-safe past the config-load boundary — methods never observe `Record<string, unknown>` at runtime.

**Why this shape:**

- `Request`/`Response` are Web Fetch standards, supported by every runtime (Node 18+, Bun, Deno, Workers, Lambda via shims). Methods written against this are portable.
- Methods construct `Response` themselves when needed (e.g., for HTML rendering: `new Response(body, { headers: { "content-type": "text/html" } })`) or use small framework-agnostic helpers from `idp/util/http.ts`.
- No JSX in the type. Methods that want server-rendered JSX import the JSX runtime themselves and stringify to HTML before constructing the `Response`. The type contract stays neutral.

**Response sanitization — cookie policy is enforceable.** Returning an arbitrary `Response` would let a method stuff `Set-Cookie` headers in and bypass framework-owned cookie policy. To prevent that, the HTTP layer **strips a fixed allowlist-violating set of headers from every method-returned `Response` before sending it**, then merges in `SetCookie[]` data through the framework's own serializer. Concretely:

- **Stripped from method `Response`** (logged as a warning at ERROR level — programmer bug):
  - `Set-Cookie`, `Set-Cookie2`
  - `Strict-Transport-Security`, `Content-Security-Policy`, `Content-Security-Policy-Report-Only`
  - `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
  - `Cache-Control` (framework sets a conservative default; methods opt in via the typed `cache?: CachePolicy` field on `MethodResult.challenge` — see `CachePolicy` in `types/method.ts` above). Methods cannot set `Cache-Control` directly.
- **Cookies applied from `SetCookie[]`** through the framework's serializer, which enforces:
  - `Secure` forced on in production environments.
  - `SameSite` defaulted to `Lax` if not specified.
  - `HttpOnly` defaulted to true for any cookie name matching `auth.*` / `idp.*` (the framework's reserved namespace).
  - Cookie domain and path defaults from `IdPOptions`.

CI lint additionally flags methods that import `cookie`/`set-cookie-parser` directly to catch bypass attempts at build time.

**`providerSubject` vs final subject — who creates what.** Roles are explicit:

- The **method's `success` result** carries `providerSubject` (the upstream system's stable identifier — Google's `sub`, GitHub's `id`, the password row's `user_id`, the passkey's credential-bound user handle) and `properties` (typed claims emitted by the method — email, name, scopes granted by upstream, etc.). The method never constructs the final subject identity the IdP issues.
- The **user-supplied `IdPOptions.success` callback** (required) maps `({ tenant, methodId, methodKind, providerSubject, properties, context }) → SubjectClaim` (see `SuccessMapInput` below). This is where the user looks up or creates a stable internal user record, decides what subject type to issue (`"user"` vs `"admin"` vs `"system"`), and returns the typed subject claim that becomes the JWT subject. This is the same role the current `auth.success` callback plays in `issuer.ts`. It is a required hook, not an observability hook.
- `IdPOptions.hooks.onSuccess` (optional) is for **observation only** — audit logs, analytics, side effects. It does not influence the issued subject and runs after the subject claim is constructed.

**Relevant fields on `IdPOptions` (fragment — canonical definition below in _IdP construction_):**

```ts
// success is REQUIRED. Maps method output → issued subject. Runs at /token time, after PKCE check.
success: (input: SuccessMapInput) => Promise<SubjectClaim>

// hooks.onSuccess is OPTIONAL and observation-only — does not influence the issued subject.
hooks?: {
  onSuccess?: (event: SuccessEvent) => Promise<void>
  onFailure?: (event: FailureEvent) => Promise<void>
}
```

**Why this shape works for all 22 existing providers:**

`MethodType` is the canonical discriminator: `"oauth2" | "oidc" | "password" | "code" | "m2m" | "passkey" | "custom"`. Each existing provider lands on exactly one of those.

| Existing provider                                                                                                             | `MethodType`           | Routes it declares                                                                                                             |
| ----------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| google, github, apple, discord, facebook, linkedin, microsoft, slack, spotify, twitch, x, yahoo, jumpcloud, keycloak, cognito | `"oidc"` or `"oauth2"` | `GET /authorize`, `GET /callback`                                                                                              |
| `oauth2`, `oidc`, `arctic` (generic building blocks)                                                                          | `"oauth2"` / `"oidc"`  | Same two routes; users wrap with config                                                                                        |
| `password`                                                                                                                    | `"password"`           | `GET /authorize`, `POST /login`, `POST /register`, optional `POST /forgot`                                                     |
| `code` (magic code)                                                                                                           | `"code"`               | `GET /authorize`, `POST /send`, `POST /verify`                                                                                 |
| `m2m`                                                                                                                         | `"m2m"`                | `POST /token` (handled at top level) — actually just a `client` fn, no routes                                                  |
| `passkey`                                                                                                                     | `"passkey"`            | `GET /authorize`, `POST /authenticate-options`, `POST /authenticate-verify`, `POST /register-request`, `POST /register-verify` |

The OAuth/OIDC family share enough that they become two reusable methods (`oauth2Generic`, `oidcGeneric`) parameterized by config — port the 15+ specific providers as ~10-line wrappers around those.

### Tenant Recovery Across Redirects

`resolveTenant(req)` works for the first request in a flow (subdomain, header, JWT, mTLS, etc.). It does **not** work reliably for the callback from an upstream OAuth provider: by the time Google redirects the user to `/google/callback?state=…&code=…`, the original tenant signal may be gone (header stripped, cookie partitioned across IdP host vs. tenant app host, JWT claim long expired).

The plan handles this with an **ordered recovery chain**, evaluated by the framework before `resolveTenant` runs:

**Unified design.** Both the primary and fallback paths use a single underlying mechanism: a strong, single-use, server-side **flow record** in `SessionStore`. They differ only in how `flowId` survives the round trip back from the upstream provider. This minimizes what gets exposed in URLs and gives a single comparison point at token issuance ("does the flow record still match the request?").

The flow record is the source of truth for everything tied to the in-flight authorization. The `state` parameter and callback URL never carry sensitive details:

```ts
// types/flow.ts — what SessionStore persists per in-flight authorization
type FlowRecord = {
  flowId: string // 128-bit random
  tenantId: TenantId

  // The id/kind split is carried through every runtime contract.
  methodId: string // tenant-local instance id = MethodConfig.id, e.g. "google-workspace"
  methodKind: string // factory kind        = MethodConfig.kind, e.g. "google"

  // RP/client side (the application calling our IdP)
  clientId: string // app-side OAuth client
  appRedirectUri: string // final redirect to the relying party (app)
  callbackPath: string // where this flow is allowed to land on the IdP
  callbackHost: string // host this flow is allowed to land on
  appState: string | null // the relying party's `state` param, echoed back at success
  scopes: string[] // requested at /authorize
  responseType: "code" // OAuth 2.1: code only. Implicit ("token") removed; see note below.
  audience?: string
  prompt?: string[] // standard OIDC prompt values (none, login, consent, ...)
  uiLocales?: string[]
  nonce: string // CSRF nonce, distinct from `appState`
  clientPkce?: { challenge: string; method: "S256" } // RP/client → IdP PKCE; required for public clients

  // Method-private state (the IdP acting as OAuth client of an upstream provider,
  // or any other method-internal callback-time data)
  methodState?: unknown // typed per method via generics on AuthMethod<P, S>
  // Examples:
  //   - OAuth provider: { upstreamPkceVerifier, upstreamState }
  //   - OIDC provider: { upstreamPkceVerifier, upstreamNonce }
  //   - Passkey: { challenge, allowedCredentialIds }
  //   - Password: typically null (no callback)

  context?: Record<string, unknown> // user's requestContext snapshot, if any
  createdAt: number
  expiresAt: number // see TTL discussion below — pre-callback lifetime, NOT auth-code lifetime
}
```

**OAuth 2.1 — `code` only.** OAuth 2.1 removes the implicit grant (`response_type=token`), citing the security issues with tokens in URL fragments. The new IdP only supports `response_type=code` (with PKCE). Applications that historically used the implicit grant migrate to authorization-code + PKCE, which works on SPAs and public clients without backchannel secrets. Token-in-fragment behavior is **not** in scope for the rebuild. If a legacy client genuinely needs it, that's a deliberate decision documented separately — not a default.

**Two PKCEs, never confuse them:**

- `clientPkce` is the **RP/client → our IdP** PKCE. The relying party generates the verifier and sends the challenge to `/authorize`. Stored in `FlowRecord.clientPkce`; verified at `/token` against the RP's `code_verifier`.
- The **our IdP → upstream provider** PKCE (when we act as an OAuth client of Google/GitHub/etc.) lives inside `methodState` for the upstream-OAuth methods, where the method handler stashes the upstream verifier at `/authorize` time and reads it at the upstream `/callback`. The framework never inspects this; it's opaque per method.

**Flow record lifecycle — when the framework writes, consumes, and disposes of it.** The contract is explicit and the **flow record is consumed exactly once**, before the method's callback handler runs. The handoff then snapshots from the in-memory record — there is no second `consumeFlow` call.

1. **Create.** At `/authorize`, after schema validation and after `resolveTenant` succeeds, and **before** dispatching to the method's `GET /authorize` handler: the framework atomically creates a `FlowRecord` in `SessionStore` with all RP/client-side fields populated (`tenantId`, `clientId`, `appRedirectUri`, `appState`, `scopes`, `audience`, `clientPkce`, `nonce`, `context`, `methodId`, `methodKind`, `callbackHost`, `callbackPath`). `methodState` is initialized to `null`. The framework mints the MACed `state` envelope (`{ tenantId, flowId, nonce, kid }`) and attaches the record to `MethodContext.flow`. `callbackPath` is computed at this point — see _Callback path conventions_ below — so the exact-match check at step 3 has the right target.
2. **Update (on `challenge`).** When the method handler returns `{ kind: "challenge", response, saveMethodState? }`, if `saveMethodState` is set the framework merges it into `FlowRecord.methodState` and persists the updated record **before** returning the `Response` to the user agent. For a typical redirect-based OAuth method, this is where the upstream PKCE verifier, upstream nonce, and upstream state get persisted. Atomicity guarantee: the user agent never sees the upstream redirect until `methodState` is durably saved.
3. **Consume (single, on callback).** On the upstream callback, after MAC verification of `state` and identity checks (see _State-flow consistency_ below), the framework calls `SessionStore.consumeFlow(flowId)` exactly once. The returned `FlowRecord` is held in memory for the remainder of the request and passed to the method's `GET /callback` handler via `MethodContext.flow` and `MethodContext.methodState`. The record is gone from `SessionStore` at this point — methods cannot rely on it being readable a second time, and the framework does not call `consumeFlow` again.
4. **Snapshot + dispose.** If the method returns `success`, the framework snapshots the relevant fields from the in-memory `FlowRecord` (already in scope from step 3) into the auth-code payload via `TokenStore.saveCode`. `methodState` is **not** snapshotted — it served its callback purpose and is dropped. If the method returns `denied`/`error`, the in-memory record is discarded; no snapshot is written.

Methods may not call `SessionStore` directly to mutate the flow record. The framework owns flow-record I/O; methods only observe (`MethodContext.flow`) and request updates (`MethodResult.challenge.saveMethodState`).

**Callback path conventions.** `FlowRecord.callbackPath` stores the **full expected request pathname for this specific flow**, computed at flow creation. The value depends on which recovery mechanism the flow uses:

| Recovery mechanism                     | `callbackPath` value (example)      | Why                                                                     |
| -------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------- |
| #1 MAC-bound `state`                   | `/cb/google-workspace`              | Path is fixed per (tenant, method instance). `flowId` rides in `state`. |
| #2 Partitioned callback host + `state` | `/cb/google-workspace`              | Same as #1; host carries tenant, `state` carries `flowId`.              |
| #3 `flowId` in URI (path-embedded)     | `/cb/google-workspace/abc-flow-123` | Path includes `flowId`. Each flow has a unique `callbackPath`.          |
| #3 `flowId` in URI (query-embedded)    | `/cb/google-workspace`              | Path is fixed; `flowId` is in query string, compared separately.        |

The exact-match check at step 3 of the lifecycle compares `request.url.pathname` against `flowRecord.callbackPath` directly. Each flow stores the path it expects, so exact-match works uniformly across mechanisms. The framework picks the recovery mechanism at `/authorize` time (based on `IdPOptions` configuration and the method's preference), computes `callbackPath` accordingly, then stamps it onto the `FlowRecord` and the registered redirect URI sent to the upstream.

**State-flow consistency check.** After `consumeFlow` returns the record, before dispatching to the method's callback handler, the framework MUST verify:

```ts
// After: state MAC verifies, flowRecord = await sessionStore.consumeFlow(flowId)
if (stateEnvelope.tenantId !== flowRecord.tenantId)
  return invalidRequest("tenant mismatch")
if (stateEnvelope.nonce !== flowRecord.nonce)
  return invalidRequest("nonce mismatch")
// Bound the request to the registered callback location:
if (request.url.host !== flowRecord.callbackHost)
  return invalidRequest("host mismatch")
// Exact match after URL normalization — startsWith would let /cb match /cb-attacker.
{
  const reqPath = new URL(request.url).pathname.replace(/\/+$/, "")
  const expected = flowRecord.callbackPath.replace(/\/+$/, "")
  if (reqPath !== expected) return invalidRequest("path mismatch")
}
```

This is the explicit security invariant. The MAC proves the envelope wasn't tampered with; the tenant + nonce comparison against the consumed record proves the envelope corresponds to _this_ flow record and not another. Without it, `nonce` is decorative. Any mismatch → `invalid_request`, audit `flow_replay_attempt` (or `flow_tenant_mismatch` / `flow_callback_mismatch` as appropriate).

**Flow TTL vs. auth-code TTL — distinct lifetimes.** These are different lifetimes and must not be conflated:

- **Flow record TTL (default 10 minutes).** Covers the pre-callback span: user logs into the upstream IdP, completes MFA, accepts consent, switches between mobile browser tabs, recovers from a backgrounded app, etc. 60s is far too short for normal OAuth sign-ins and will cause user-visible failures. Industry norm is 10-15 minutes (Auth0: 10m, Okta: 15m).
- **Auth-code TTL (default 60 seconds).** Covers the post-callback span: the IdP has issued the code, the user-agent posts it back to the relying party, the RP exchanges it at `/token`. Must be very short per OAuth 2.1 BCP.

Recovery mechanisms, in order of preference:

1. **Minimal MAC-bound `state` (default).** When redirecting to the upstream provider, the IdP mints a `state` parameter that is **only** `{ tenantId, flowId, nonce, kid }` MACed with HMAC-SHA-256 using a global state key (chicken-and-egg: tenant config can't be loaded until we know the tenant, so the key has to be global). `state` is base64url-encoded and intentionally small (well under 256 bytes) to stay clear of provider URL limits. **No sensitive data — client_id, redirect_uri, etc. — is ever in `state`.** On callback the framework executes a fixed sequence: (a) parse `state` and verify the MAC under the `kid`-indexed key — invalid MAC short-circuits to `invalid_request`; (b) `await sessionStore.consumeFlow(flowId)` (single, atomic delete-on-read); (c) compare envelope ↔ record (`state.tenantId === flow.tenantId`, `state.nonce === flow.nonce`) and request ↔ record (`callbackHost`, `callbackPath` per the exact-match check in _State-flow consistency check_); (d) dispatch to the method's callback handler with the in-memory `FlowRecord`. `resolveTenant` is **not** consulted when `state` verifies.

2. **Tenant-partitioned callback host (tenant-resolution aid only).** Some operators prefer tenant-per-subdomain (`acme.idp.example/callback`, `beta.idp.example/callback`). Configure with `callbackHostFor: (tenantId) => string`. **The host alone is never sufficient to authorize a callback — it only tells the framework which tenant config to load. The authorization transaction must still be identified by `flowId`** obtained via mechanism #1 (MACed state) or #3 (`flowId` in URI). A callback host with no recoverable `flowId` is rejected with `invalid_request`. This mechanism reduces global key dependency for tenant resolution; it does not replace flow identification.

3. **`flowId`-in-URI fallback (hardened, narrow).** If `state` is unreachable (legacy upstreams that strip `state`, certain POST-binding cases), `flowId` travels via the **registered redirect URI**:

   - Path-embedded: `https://idp.example/cb/<methodId>/<flowId>` (preferred — providers preserve full path).
   - Query-embedded: `https://idp.example/cb/<methodId>?flowId=<flowId>` (if provider tolerates query strings in pre-registered redirect URIs).
   - **Defense in depth:** an HttpOnly/Secure/SameSite=Lax cookie named `idp.flow` containing the same `flowId` is set at `/authorize` time. On callback, if the cookie is present it must match the URI's `flowId`. If the cookie is missing (cross-site POST-binding cases), the framework requires an explicit `prompt=consent` re-auth before issuing tokens.
   - On callback: `SessionStore.consumeFlow(flowId)` → verify request's host/path equal record's `callbackHost`/`callbackPath` → atomic delete. Any mismatch → `invalid_request`, audit `flow_replay_attempt`.

   This path is intentionally narrow and used only when mechanism #1 fails. It carries no more info than `flowId` itself.

**Flow → Code handoff (explicit).** The flow record is _consumed_ (deleted) on the callback, before the auth code is minted. The framework therefore snapshots the fields needed at `/token` from the consumed `FlowRecord` into the auth-code payload:

```ts
// PRECONDITION (set up earlier in the callback handler, before the method ran):
//   1. state MAC verified
//   2. flow = await sessionStore.consumeFlow(flowId)   ← single consume, already done
//   3. state/flow consistency checks passed (tenantId/nonce/host/path)
//   4. method dispatched, returned { kind: "success", providerSubject, properties }
//
// `flow` is the in-memory FlowRecord from step 2. We do NOT call consumeFlow again.

const code = randomToken()
await tokenStore.saveCode(
  code,
  {
    tenantId: flow.tenantId,
    clientId: flow.clientId,
    appRedirectUri: flow.appRedirectUri,
    appState: flow.appState, // echoed to RP at success
    scopes: flow.scopes,
    audience: flow.audience,
    clientPkce: flow.clientPkce, // verified against RP's code_verifier at /token
    methodId: flow.methodId, // tenant-local instance id
    methodKind: flow.methodKind, // factory kind
    context: flow.context,
    providerSubject: successResult.providerSubject, // from MethodResult.success — upstream's id
    properties: successResult.properties, // typed per method
    expiresAt: now + AUTH_CODE_TTL,
  },
  AUTH_CODE_TTL,
)
// Note: responseType is omitted — OAuth 2.1 makes it implicit ("code" always).
// Note: methodState is NOT snapshotted; it served its purpose during the upstream round-trip
//       and is gone with the flow record by design.
```

`SessionStore.consumeFlow` is contractually required to return the full `FlowRecord` (not just `void`) so this snapshot is possible. At `/token`, all validation reads from the consumed code's snapshot — there is no second lookup of the flow record because it no longer exists. The token-time consistency check from `issuer.ts:705-710` carries forward as a comparison between request fields (`client_id`, `redirect_uri`, PKCE `code_verifier` against `clientPkce.challenge`) and the code-payload snapshot. Any mismatch → **`invalid_grant`** (RFC 6749 §5.2).

After validation, the framework invokes the user-supplied `IdPOptions.success` callback with `{ tenant, methodId, methodKind, providerSubject, properties, context }` to produce the final `SubjectClaim`, then mints access + refresh tokens with that claim as the JWT `sub`.

**Code payload confidentiality.** The auth-code payload contains `properties` from the method, which can include sensitive material — particularly for OAuth/OIDC methods that capture an upstream access or refresh token in `properties` so the user's `success` callback can store it for later API calls. Contract for `TokenStore.saveCode` / `consumeCode`:

- **Encrypted at rest.** Payloads are encrypted with a key from `KeyStore` (the existing encryption-key abstraction) before being written. Adapters must support this; the in-memory adapter still encrypts to exercise the path. The plaintext payload never touches durable storage.
- **Short-lived.** Auth-code TTL is 60 seconds; the framework refuses to write a code with a longer TTL.
- **Single-use.** `consumeCode` is atomic delete-on-read (consistent with the existing contract); a successful consume returns the decrypted payload, after which the row is gone.
- **Never logged.** Audit log events related to code issuance and consumption may record `{ tenantId, clientId, methodId, methodKind, codeId-hash }` but **never** the payload contents. Adapter logs (DB query logs, OTEL spans) must mask payload bodies.
- **Alternative split.** Adapters or callers preferring stricter isolation MAY split: keep claim-only data in the code payload and store upstream tokens via an explicit `IdPOptions.persistUpstreamTokens?: (input) => Promise<void>` hook. **The hook runs at `/token` time, after the client is authenticated, after the redirect URI is verified, after PKCE has succeeded, and after the user's `success` callback has produced a `SubjectClaim`** — but before the access/refresh response is returned to the RP. Running the hook here, not at callback time, avoids persisting upstream tokens for flows that ultimately fail at `/token` (PKCE mismatch, client mismatch, abandoned code) and avoids creating side effects in audit/secrets stores for those failed exchanges. The hook receives `{ tenant, methodId, methodKind, providerSubject, properties, subjectClaim }` (same id/kind shape as `SuccessMapInput`); if it throws, the IdP responds with OAuth `server_error` (RFC 6749 §5.2) and the token issuance is aborted; the original exception is captured as `cause` for audit but not returned to the RP. This is documented as a Phase 5 escape hatch for high-sensitivity deployments; the default in-tree path is "encrypted code payload" since it's simpler and adequate for most use cases.

**Mechanism:**

```ts
// types/tenant.ts
// Every callback recovery carries a flowId. Tenant alone is never sufficient.
export type TenantRecovery =
  | { kind: "mac-state"; tenantId: TenantId; flowId: string }
  | { kind: "host-plus-uri"; tenantId: TenantId; flowId: string } // tenant from host, flowId from URI
  | { kind: "host-plus-mac"; tenantId: TenantId; flowId: string } // tenant from host, flowId from MACed state
  | { kind: "flow-id-in-uri"; tenantId: TenantId; flowId: string } // no host partitioning, flowId in URI
  | { kind: "fresh-request" } // first request in flow, defer to resolveTenant; no callback semantics

// Order of evaluation, framework-internal:
//   1. If callbackHostFor configured AND request host matches a known tenant:
//        a. If `state` MAC-verifies → host-plus-mac
//        b. Else if `flowId` in URI → host-plus-uri
//        c. Else → reject (invalid_request, audit unrecoverable_flow)
//   2. Else if `state` MAC-verifies → mac-state
//   3. Else if `flowId` in registered URI path/query → flow-id-in-uri
//   4. Else → fresh-request → call user's resolveTenant(req)
//
// On any *-flow recovery: SessionStore.consumeFlow(flowId) must succeed;
//   failure → invalid_request, audit replay_attempt.

// Relevant fields on IdPOptions for tenant recovery (fragment — canonical definition in *IdP construction*):
//   resolveTenant:    (req: Request) => Promise<Result<TenantId, AuthError>>
//   callbackHostFor?: (tenantId: TenantId) => string                   // opt-in for partitioned hosts
//   stateKeys:        StateKeyRing                                     // REQUIRED — see below

// Key ring supports rotation with overlap. Active key mints new state;
// any key in `verify` accepts existing state during its overlap window.
export type StateKeyRing = {
  active: { kid: string; key: Uint8Array } // 32 bytes, HMAC-SHA-256
  verify: ReadonlyArray<{ kid: string; key: Uint8Array }> // includes `active` + previous overlapping keys
}
```

**Why a global key for `state`:** the recovery has to work _before_ tenant config is loaded. Tenant-scoped keys would create a bootstrap problem. The global key MACs only `{ tenantId, flowId, nonce, kid }` — nothing sensitive. Everything else (client, redirect, PKCE, context) lives in the server-side flow record.

**Crypto — HMAC-SHA-256 (symmetric MAC), not signatures.** All IdP instances share the key material and use it for both minting and verifying state envelopes. There's no use case here for distributed verification by parties outside the IdP cluster, so the asymmetric overhead of Ed25519 buys nothing.

**Key ownership and rotation.** The canonical API is **direct construction option** (`IdPOptions.stateKeys: StateKeyRing`) — passed in at bootstrap. This avoids a circular dependency on `KeyStore` for the most critical security material and makes the requirement explicit at construction time. For operators who prefer storing the key ring in `KeyStore` under a reserved id, a helper `loadStateKeyRingFromKeyStore(keyStore): Promise<StateKeyRing>` is provided. Rotation cadence: monthly, with an overlap window **at least as long as the flow record TTL** (default 10 minutes, so a 1-hour overlap leaves plenty of headroom). New keys are added to `verify` first, promoted to `active` on the next rotation, then dropped from `verify` after the overlap window.

**Security properties to preserve:**

- The `state` MAC binds `tenantId` to the flow. An attacker can't forge a callback for tenant A using state minted for tenant B.
- The current implementation's "tenantId mismatch" check at success (`issuer.ts:705-710`) carries forward: at `/token`, the framework compares the recovered tenantId against what was snapshotted into the auth-code payload at callback time. Mismatch → `invalid_grant` (RFC 6749 §5.2 — the `/token` endpoint's standard error code for a code whose context no longer matches).
- `state` MAC + per-flow nonce + short TTL = CSRF-resistant by construction. No tenant-specific state required.

### Port Consistency Requirements

Storage ports differ in their consistency needs. Adapter implementations must meet the per-method requirement or the adapter is unsafe to use.

| Port           | Method                                              | Required                                                                                                     | Why                                                                                                                                                                                           |
| -------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TokenStore`   | `saveCode(code, payload, ttl)`                      | **Strong, atomic.** Payload **encrypted at rest** with `KeyStore` encryption key; TTL ≤ auth-code TTL (60s). | Code must be created exactly once, visible immediately. Payload may contain upstream tokens; see _Code payload confidentiality_.                                                              |
| `TokenStore`   | `consumeCode(code)`                                 | **Strong, compare-and-swap.** Returns decrypted payload on success.                                          | Single-use; second consumption must fail deterministically.                                                                                                                                   |
| `TokenStore`   | `saveRefresh(refresh, payload)`                     | **Strong, atomic**                                                                                           | New refresh tokens issued during rotation must be immediately retrievable.                                                                                                                    |
| `TokenStore`   | `consumeRefresh(refresh, options)`                  | **Strong, CAS with reuse-detection window**                                                                  | The core of refresh-token rotation security. Must atomically check-and-mark; concurrent presentations of the same token resolve to one winner, others trigger reuse-detection (revoke chain). |
| `TokenStore`   | `revokeBySubject(subject)`                          | Strong (preferred), eventual acceptable with documented lag                                                  | Revocation must propagate quickly but a few seconds of lag is tolerable.                                                                                                                      |
| `SessionStore` | `saveFlow(flowId, payload, ttl)`                    | **Strong, atomic**                                                                                           | Flow record must be visible immediately on the callback request.                                                                                                                              |
| `SessionStore` | `consumeFlow(flowId)`                               | **Strong, atomic delete-on-read** that **returns the `FlowRecord`** (CAS or `DELETE … RETURNING`)            | Single-use. Concurrent consumption must resolve to exactly one winner. Returns the record so the framework can snapshot fields into the auth-code payload before they're lost.                |
| `SessionStore` | `create/read/revoke` (long-lived sessions, if used) | **Strong**                                                                                                   | Session creation must be immediately readable on next request.                                                                                                                                |
| `KeyStore`     | `currentSigningKey()`                               | Strong                                                                                                       | Active key must be unambiguous.                                                                                                                                                               |
| `KeyStore`     | `signingKeys()` (JWKS)                              | Eventual OK (with TTL)                                                                                       | Verifiers tolerate brief JWKS lag during rotation.                                                                                                                                            |
| `ConfigStore`  | `getTenantConfig(id)`                               | **Eventual + bounded staleness (TTL ≤ 60s)**                                                                 | Read-heavy, write-rare. Cache aggressively, invalidate on update.                                                                                                                             |
| `MethodStore`  | `getMethodConfig(tenant, methodId)`                 | Same as ConfigStore                                                                                          | Subset of tenant config.                                                                                                                                                                      |
| `AuditLog`     | `log(event)`                                        | Append-only, durable                                                                                         | Loss = audit gap; ordering across instances not required.                                                                                                                                     |

**Implication for adapter choice:**

- **Cloudflare KV is acceptable** for `ConfigStore`, `MethodStore`, and `KeyStore.signingKeys()` (read-heavy, tolerates eventual).
- **Cloudflare KV is NOT acceptable** for `TokenStore` refresh/code methods. Use **D1** (SQLite with strong consistency), **Durable Objects** (strongly consistent state machines), or **DynamoDB with conditional writes**.
- **In-memory adapter** trivially satisfies all consistency requirements (single process, no concurrency below tokio/uv-loop level). Fine for tests and single-instance dev.
- **Postgres** satisfies all with row-level locking / `SELECT FOR UPDATE` on the refresh path.

Phase 1 must produce a `ports/CONSISTENCY.md` doc enumerating these contracts. Phase 6 adapters that don't meet them are not certified for production.

### IdP construction

```ts
// index.ts
export type IdPOptions = {
  resolveTenant: (req: Request) => Promise<Result<TenantId, AuthError>>
  callbackHostFor?: (tenantId: TenantId) => string // opt-in for partitioned callback hosts (recovery #2)
  stateKeys: StateKeyRing // HMAC-SHA-256 key ring for state envelopes — REQUIRED
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  sessionStore: SessionStore // required: flow records need strong CAS / atomic delete-on-read
  auditLog?: AuditLog // optional but recommended
  issuerUrl: string | ((req: Request) => string)
  methods: Record<string, AuthMethodFactory> // available method implementations. KEY MUST EQUAL factory.kind; createIdP() throws if any key disagrees with its factory's kind, with a list of offending keys in the error message.
  subjects: SubjectSchema

  // REQUIRED. Maps method result → issued subject. Runs at /token time, after PKCE check.
  // Same conceptual role as the existing auth.success callback in issuer.ts.
  success: (input: SuccessMapInput) => Promise<SubjectClaim>

  theme?: ThemeConfig
  hooks?: {
    onSuccess?: (event: SuccessEvent) => Promise<void> // observation only — does NOT influence the subject
    onFailure?: (event: FailureEvent) => Promise<void>
  }
}

export type SuccessMapInput = {
  tenant: TenantContext
  methodId: string // tenant-local instance id (MethodConfig.id)
  methodKind: string // factory kind (MethodConfig.kind)
  providerSubject: string
  properties: unknown // typed at call site via the method's P
  context: Record<string, unknown> | null
}

export type IdP = {
  handle: (req: Request) => Promise<Response>
  // also expose primitives for advanced users:
  authorize: (req: Request) => Promise<Response>
  token: (req: Request) => Promise<Response>
  userinfo: (req: Request) => Promise<Response>
  // etc.
}

export function createIdP(opts: IdPOptions): IdP
```

**Usage:**

```ts
const idp = createIdP({
  resolveTenant: async (req) => {
    const slug = req.headers.get("x-org-slug")
    if (!slug)
      return err({
        code: "tenant_not_found",
        description: "missing x-org-slug",
        tenantId: "",
      })
    return ok(slug as TenantId)
  },
  stateKeys: {
    // HMAC-SHA-256 key ring; rotated monthly with overlap
    active: { kid: "2026-05", key: env.IDP_STATE_KEY_CURRENT },
    verify: [
      { kid: "2026-05", key: env.IDP_STATE_KEY_CURRENT },
      { kid: "2026-04", key: env.IDP_STATE_KEY_PREV }, // overlap during rotation
    ],
  },
  // or: stateKeys: await loadStateKeyRingFromKeyStore(keyStore)
  configStore: new D1ConfigStore(env.DB), // strongly consistent — fine for read-heavy config
  tokenStore: new D1TokenStore(env.DB), // MUST be strongly consistent — KV is NOT acceptable here
  sessionStore: new DOSessionStore(env.SESSIONS), // Durable Object — strong consistency for flow records
  keyStore: new D1KeyStore(env.DB),
  auditLog: new ClickhouseAuditLog(env.AUDIT_URL),
  issuerUrl: (req) => new URL(req.url).origin,
  methods: {
    google: googleMethod(),
    password: passwordMethod({ hash: "argon2" }),
    passkey: passkeyMethod({ rpName: "Acme" }),
  },
  subjects,
  success: async ({
    tenant,
    methodId,
    methodKind,
    providerSubject,
    properties,
  }) => {
    // methodKind tells you WHICH provider this came from (e.g. "google").
    // methodId tells you WHICH INSTANCE (e.g. "google-workspace" vs "google-personal").
    // Use methodKind for provider-specific logic; use methodId for instance-specific routing.
    const user = await db.users.upsertFromProvider(
      tenant.id,
      methodKind,
      providerSubject,
      properties,
    )
    return { type: "user", properties: { userId: user.id, email: user.email } }
  },
})

export default { fetch: idp.handle } // Cloudflare Workers
```

Multi-tenancy is now **invisible to the framework** — `resolveTenant` returns an id, the framework loads config, methods receive a `TenantContext`. No `/tenant/:id/*` URLs. No `function`-vs-`object` provider config split.

---

## Phase Plan

Each phase has: **Goal**, **Deliverables**, **Acceptance Criteria**, **Risks**. Phases are mostly sequential but parallel work is called out.

### Phase 1 — Domain Types & Project Skeleton ✅ **COMPLETE**

**Goal:** Lock down the type system. Get the abstractions right before writing logic.

**Deliverables:**

- `packages/openauth/src/` reorganized to the target layout (existing `issuer.ts` / `provider/` / `storage/` left untouched in this phase; new directories created empty alongside them).
- All files under `types/` and `ports/` populated.
- `types/method.ts` with zero framework imports (CI lint rule enforces).
- `types/tenant.ts` includes `TenantRecovery`, `StateKeyRing`, and the minimal state envelope schema (`{ tenantId, flowId, nonce, kid }`).
- `types/flow.ts` defines `FlowRecord` (the single source of truth for in-flight authorization state).
- `ports/session-store.ts` includes the explicit `saveFlow(flowId, payload, ttl)` and `consumeFlow(flowId)` methods with documented atomicity requirements.
- `ports/CONSISTENCY.md` enumerating per-method consistency contracts (the table in this plan, formalized) — including the new flow ops.
- `index.ts` exports the public types and a stub `createIdP` that throws "not implemented."
- A doc file `packages/openauth/ARCHITECTURE.md` explaining the model, the recovery chain, and the consistency contracts.
- No runtime logic. Type-only.

**Acceptance criteria:**

- `bun run typecheck` passes with `strict: true`.
- All AuthMethod / Result / Error / TenantContext / Port / TenantRecovery types reviewed and signed off.
- Consistency contracts in `ports/CONSISTENCY.md` reviewed and signed off.
- `types/method.ts` has no imports from `hono`, `node:*`, or any HTTP framework (CI lint).
- Open questions in this plan are resolved.

**Risks:**

- Premature type lock-in. Mitigation: keep types in one phase so we can iterate fast before any logic depends on them.

**Estimated effort:** 2-3 days.

#### Phase 1 — Shipped

- Directory skeleton: `src/{types,ports,domain,http/{handlers,middleware,schemas},methods/providers,adapters/memory,util}/` created alongside legacy `issuer.ts`/`provider/`/`storage/`/`ui/`. Legacy files untouched.
- `types/`: `result.ts`, `error.ts`, `tenant.ts`, `flow.ts`, `method.ts`, `authorization.ts`, `token.ts`, `subject.ts`, `idp.ts`.
- `ports/`: `config-store.ts`, `token-store.ts`, `session-store.ts`, `key-store.ts`, `audit-log.ts`, `method-store.ts`, plus `CONSISTENCY.md`.
- Public API: `src/index.ts` re-exports every new public type and adds a `createIdP(_opts) => IdP` stub that throws `"createIdP: not implemented (Phase 1 ships types only)"`. Legacy `issuer` / `createClient` / `createSubjects` exports kept so `master` keeps compiling.
- `packages/openauth/ARCHITECTURE.md` written — model overview, id/kind split, tenant-recovery chain, flow-record lifecycle, response sanitization, TTL table, port-consistency summary, phase status table.
- `zod ^3.24.1` added to `packages/openauth/package.json` dependencies (required by `AuthMethodFactory.configSchema: z.ZodType<Cfg>`).
- **Verification gates passed:** `bunx tsc --noEmit -p tsconfig.json` exits 0 under `strict: true`; full legacy test suite (`bun test`, 67 tests) still green; `grep` confirms no `hono` or `node:*` imports under `src/types/` or `src/ports/`; the `createIdP` stub throws as documented at runtime.

#### Phase 1 — Deferred

- **CI lint rule** for "no framework imports in `types/` and `ports/`" is verified manually this phase (grep); the actual CI job lands in Phase 2 alongside the matching rule for `domain/` (`domain/` cannot import `hono`). One job, two glob patterns.
- **Long-lived session methods** on `SessionStore` (`createSession` / `readSession` / `revokeSession`) are typed but optional. Decision on whether the framework uses them at all (vs. issuing only refresh-token-backed sessions) is deferred to Phase 2.

#### Phase 1 — Decisions captured for later phases

- **`AuditEvent` taxonomy is now closed and named.** The framework audits a fixed set of event kinds — listed in `ports/audit-log.ts` — including `flow_replay_attempt`, `flow_tenant_mismatch`, `flow_callback_mismatch`, `factory_id_mismatch`, `invalid_method_config`, `unknown_method_kind`, `unrecoverable_flow`, `refresh_reuse_detected`. Phase 2 emits these from the domain; Phase 3 emits HTTP-layer variants. Custom user events go through `{ kind: "custom", type, data }`.
- **`MethodStore` is an optional override** of the methods slice of `ConfigStore`, not a parallel source of truth. `IdPOptions.methodStore` defaults to "fall back to `ConfigStore`." Phase 2 wires this fallback explicitly so Phase 7 (console) can route method-config writes through `MethodStore` independently of the rest of tenant config.
- **`SubjectSchema` stays library-agnostic** at the type boundary (`Record<string, v1.StandardSchema>`). Zod 3.24+ implements Standard Schema v1, so AD4 "standardize on Zod" applies to **framework-internal** schemas (`AuthMethodFactory.configSchema`, HTTP request schemas) — users can keep their existing Valibot / Arktype subject definitions without rewriting them. Documented in `types/subject.ts` JSDoc.
- **`RefreshTokenPayload.family` is the rotation chain id.** Reuse detection is implemented as `revokeFamily(family)` (Phase 2). Carried on `AuditEvent.refresh_reuse_detected` for forensics.
- **`AccessTokenClaims.tid` / `mid` / `mkind`** — short-named JWT custom claims that carry tenant id, method instance id, and method factory kind. Resource servers can route based on `mkind` without re-querying the IdP.
- **`CodePayload.methodState` deliberately omitted.** The plan §"Flow → Code handoff" calls this out; the type system now enforces it (the `CodePayload` shape simply doesn't have the field).
- **Auth-code TTL is enforced at the port boundary**, not just in domain code: `TokenStore.saveCode`'s contract (and the JSDoc on the port) says implementations must reject `ttl > 60`. Belt-and-suspenders: Phase 2 domain also validates before calling, but no adapter that satisfies the contract can be tricked into a longer-lived code.

##### Open items surfaced during Phase 1

- The "registered redirect URI" stored on `ClientConfig` needs a schema decision before Phase 3 wires the OAuth `/authorize` validator. Strawman: exact-match against `ClientConfig.redirectUris`, no wildcards, no path-suffix matching. Confirm in Phase 3 design.
- `KeyStore.SigningKey.privateKeyRef: unknown` is intentionally opaque so KMS-backed adapters can hold ARNs without leaking the private material into types. Phase 6 documents the per-adapter contract.

---

### Phase 2 — Domain Logic + In-Memory Adapters ✅ **COMPLETE**

**Goal:** Implement the OAuth/OIDC flows as pure functions over typed ports. **No framework imports** (no Hono, no Express). Domain code may accept `Request` and return `Response` since those are Web Fetch standards — the constraint is "no framework," not "no HTTP types." Testable with memory adapters.

**Deliverables:**

- `adapters/memory/` — `MemoryConfigStore`, `MemoryTokenStore`, `MemoryKeyStore`, `MemorySessionStore`, `MemoryAuditLog`. All Map-backed.
- `domain/authorize.ts` — `startAuthorize(req, tenant, ports) → Result<AuthorizationState | Response, AuthError>`. Validates request, runs `allow()`-style policy hook, persists state, returns either a challenge response (select UI / method redirect) or a state object.
- `domain/token.ts` — `exchangeCode(...)`, `issueTokens(...)`. JWT signing, refresh token generation.
- `domain/refresh.ts` — refresh token rotation, reuse detection, retention window. Port from current `issuer.ts:1042-1297`.
- `domain/revoke.ts` — token revocation.
- `domain/introspect.ts` — token introspection.
- `domain/userinfo.ts` — userinfo for OIDC.
- `domain/discovery.ts` — metadata document generation.
- `domain/pkce.ts` — PKCE validation (port `pkce.ts`).
- `domain/jwt.ts` — JWT helpers (port `jwt.ts`).
- Full unit test suite for each domain function. Use memory adapters. Cover happy + error paths.

**Acceptance criteria:**

- All flows implemented as pure functions: `(input, ports) → Promise<Result<output>>`.
- `bun test` passes with >85% coverage on `domain/`.
- No imports from `hono`, `node:*`, or any HTTP library inside `domain/`.
- A test demonstrates the full authorize → token → refresh → revoke loop with memory adapters.

**Risks:**

- Domain leaks framework concerns (e.g., cookies as ports). Mitigation: cookies are HTTP-layer; domain returns `{ setCookies: [...], response: ... }` or similar, HTTP layer applies.

**Estimated effort:** 1.5-2 weeks.

#### Phase 2 — Shipped

- **`adapters/memory/`** — `MemoryConfigStore`, `MemoryTokenStore` (encrypted-at-rest code payloads via JOSE A256GCM; atomic CAS consume; refresh reuse detection auto-revokes the family), `MemoryKeyStore` (auto-generates ES256 signing + A256GCM encryption keys on first read), `MemorySessionStore` (`saveFlow` / `updateFlowMethodState` / atomic `consumeFlow` returning full `FlowRecord`), `MemoryAuditLog` (buffered + `byKind` filter for tests). Shared `Clock` injectable so tests deterministically advance time.
- **`domain/crypto.ts`** — Web-Crypto-only helpers: `randomToken` / `randomId` / `randomHex`, HMAC-SHA-256 sign+verify (timing-safe via `crypto.subtle.verify`), AES-256-GCM compact-JWE encrypt+decrypt for code-payload at-rest encryption, base64url, SHA-256, byte/string timing-safe compare. No `node:*` imports.
- **`domain/pkce.ts`** — `s256Challenge` + `validatePkce`. S256 only per OAuth 2.1. Public-shape checks (length, type) before the hash. Timing-safe compare.
- **`domain/jwt.ts`** — `signAccessToken` (ES256/Ed25519), `verifyAccessToken` (looks up public key from `SigningKey[]` by `kid`, imports via JWK), `buildJwksDocument`.
- **`domain/state-envelope.ts`** — `mintStateEnvelope` + `verifyStateEnvelope`. Format: `b64u(payloadJson).b64u(hmacSha256)` where payload = `{tenantId, flowId, nonce, kid}`. Verify-against-any-key-in-ring to support rotation overlap. Audits `unknown_state` on malformed / unknown-kid / signature-mismatch.
- **`domain/method-cache.ts`** — Loads `MethodConfig` → validates `config` against `factory.configSchema` (Zod) → calls `factory.build(...)` → verifies `id`/`kind` round-trip → caches per `(tenantId, MethodConfig.id)`. Audits `unknown_method_kind` / `invalid_method_config` / `factory_id_mismatch`. Negative-cache for known-bad instances.
- **`domain/method-dispatch.ts`** — Builds `MethodContext` (with the new `dispatch: { state, callbackUrl, issuerUrl }` field at `/authorize` time, `null` on callbacks), invokes the handler, and persists `saveMethodState` to `SessionStore` **before** surfacing the challenge response. Methods cannot ship an upstream redirect ahead of the durably-persisted `methodState`.
- **`domain/authorize.ts`** — `startAuthorize` orchestrator. Validates client / redirect-URI exact-match / scope subset / PKCE required-when-required (public clients OR `client.pkceRequired`); resolves method (explicit `methodId`, else sole-enabled, else `select-method` UI output); creates + persists `FlowRecord`; mints state envelope; dispatches `GET /authorize`. Returns `challenge` / `issue-code` (synchronous-success short-circuit) / `denied` / `select-method`.
- **`domain/callback.ts`** — `handleCallback`. Verifies state-envelope MAC, atomic `consumeFlow` (single consume), then the **state-flow consistency check** (tenant + nonce + host + path exact match) before dispatch. Audits `flow_replay_attempt` / `flow_tenant_mismatch` / `flow_callback_mismatch` per the plan. On `success`, snapshots the in-memory `FlowRecord` into the auth-code payload (omitting `methodState`) via `TokenStore.saveCode`.
- **`domain/token.ts`** — `exchangeCode` for `grant_type=authorization_code` + shared `mintTokens`. Consumes code, client-authenticates (public: no secret; confidential: SHA-256 `secretHash` timing-safe compare — Phase 8 swaps to argon2id), verifies `redirect_uri` + RP→IdP PKCE, invokes the required `success` callback to produce the `SubjectClaim`, runs optional `persistUpstreamTokens` hook, mints JWT access + opaque refresh, saves refresh, audits `token_issued`. Subject id derived as a 22-char SHA-256 hash of canonical-JSON-encoded claim properties.
- **`domain/refresh.ts`** — `refreshTokens` for `grant_type=refresh_token`. Calls `consumeRefresh` with reuse-window option; on reuse signal (extracted from the adapter's `invalid_grant` description: `family=<id>,tenant=<id>,subject=<id>`) audits `refresh_reuse_detected`. Scope-narrowing supported; cannot exceed original grant. Family preserved across rotation via shared `mintTokens`.
- **`domain/revoke.ts`** — `revokeToken` (RFC 7009: access-token hint is a no-op; refresh consume + audit). `revokeAllForSubject` for reuse-detection escalation.
- **`domain/introspect.ts`** — RFC 7662 access-token introspection: verifies JWT against `KeyStore.signingKeys()`, returns standard claims + `tid`/`mid`/`mkind`. Garbage tokens return `active: false` (200 OK per spec).
- **`domain/userinfo.ts`** — OIDC Core §5.3 — verifies bearer, returns inlined subject `type` + `properties` + `scope`.
- **`domain/discovery.ts`** — `buildDiscoveryDocument` (with overridable paths) + `buildJwks`. Advertises `response_types: ["code"]`, `code_challenge_methods: ["S256"]` per OAuth 2.1.
- **Type-system adjustments captured forward to Phase 1 surface:**
  - Added `MethodDispatchData` field on `MethodContext` (`dispatch: { state, callbackUrl, issuerUrl } | null`). Required so a method's `GET /authorize` handler can build an upstream redirect carrying the framework-minted state envelope. Exported from `index.ts`.
  - Added `AnyAuthMethodFactory = AuthMethodFactory<any, any, any>` alias for variance-permissive map types (`IdPOptions.methods`, `MethodCacheOptions.factories`). Generic-strict `AuthMethodFactory<P, S, Cfg>` is preserved as the per-factory shape.
- **Build / tsconfig change:** `module` set to `"Preserve"` + `moduleResolution` to `"bundler"` so new code uses extensionless relative imports (user preference). Legacy code under `src/*.ts` and `src/storage/*.ts` retains `.js` extensions and continues to compile.
- **Tests (84 new, 18 files total in package):**
  - `test/domain/{crypto,pkce,state-envelope,jwt}.test.ts` — helper coverage with RFC 7636 test vector, MAC tamper-detection, encryption-at-rest plaintext-canary check.
  - `test/adapters/memory.test.ts` — encryption-at-rest verified via direct `JSON.stringify` inspection; atomic `consumeCode` / `consumeFlow`; refresh reuse-detection + family revoke; TTL > 60 s rejected.
  - `test/domain/method-cache.test.ts` — cache hit/miss; unknown-kind + factory-id-mismatch audit emission; `invalidate` drops cached entry.
  - `test/domain/authorize.test.ts` — validation failures (client / redirect / scope / PKCE), method auto-select + select-method UI branch, synchronous-success + redirect-challenge paths.
  - `test/domain/callback.test.ts` — state MAC verification (missing / unknown-key / tampered), full authorize→callback happy path, replay rejection on second consume, host-mismatch audit.
  - `test/domain/token-and-refresh.test.ts` — happy-path mint, every `exchangeCode` failure branch (consumed code / client mismatch / redirect mismatch / PKCE missing / confidential auth), refresh rotation + reuse detection + scope-narrowing constraint.
  - `test/domain/revoke-introspect-userinfo-discovery.test.ts` — revoke happy + RFC 7009 no-op + revokeAllForSubject; introspect active / inactive; userinfo bearer / garbage; discovery doc shape + JWKS.
  - `test/integration/full-flow.test.ts` — end-to-end loop: `/authorize` → method redirect → callback → `/token` (code) → introspect → refresh → reuse-detection → revoke. Single test verifying the Phase 2 acceptance criterion in one place.
- **Verification gates passed:**
  - `bunx tsc --noEmit -p tsconfig.json` exits 0 under strict.
  - `bun test` — 151/151 green (67 legacy + 84 new).
  - `grep` confirms no `hono` / `node:*` imports in `src/types/`, `src/ports/`, `src/domain/`, or `src/adapters/memory/`.
  - `bun test --coverage` — domain/ averages ~92% line coverage across all 14 files (well above the 85% gate). Individual files: pkce/jwt/introspect/userinfo/discovery/revoke at 100%; crypto 96%; refresh 99%; state-envelope 95%; method-cache 93%; token 88%; authorize 82%; callback 70%; method-dispatch 66% (the lower three are dominated by audit-failure / fallthrough branches that the in-memory adapter never triggers).

#### Phase 2 — Deferred

- **CI lint job** for "no framework imports in `types/`, `ports/`, `domain/`, `adapters/`" — still manual `grep` until Phase 3 adds the GitHub Action; the rule itself is fully defined and verified locally.
- **Long-lived session methods** — typed on `SessionStore` and the in-memory adapter implements them, but no domain function uses them yet. The framework defaults to refresh-token-backed sessions. Console authentication (Phase 7) will decide whether to wire them up; nothing in Phase 2–6 depends on the decision.
- **`flowId`-in-URI and partitioned-host recovery mechanisms (#2, #3)** — `domain/callback.ts` implements the `mac-state` recovery only. The other two mechanisms need the HTTP layer's view of `request.host` against `callbackHostFor` and of registered redirect-URI templates, so they wire in Phase 3. The type system (`TenantRecovery`) and the `FlowRecord.callbackHost`/`callbackPath` fields are already shaped to support them.
- **Discovery doc — `id_token_signing_alg_values_supported`** advertises `["ES256", "EdDSA"]` even though Phase 2 mints ES256 only. Ed25519 keystore support arrives with `MemoryKeyStore({ signingAlg: "EdDSA" })` — wired through but not exercised by tests.
- **DPoP / PAR / mTLS** scaffolding — Phase 8.

#### Phase 2 — Decisions captured for later phases

- **Method dispatch contract:** the framework persists `saveMethodState` to `SessionStore` **before** returning the challenge response. Methods cannot observe this happening — `dispatchMethod` is the single chokepoint. Phase 3's HTTP-layer dispatch should call into this function rather than re-implementing the persist-then-respond ordering.
- **Subject-id derivation** uses canonical-JSON SHA-256 over `${claim.type}\0${properties}` (truncated to 22 base64url chars). Stable for identical claims regardless of property key insertion order. Phase 3 may expose `IdPOptions.subjectIdOf?: (claim) => string` as an override if a customer needs alignment with an existing user-id scheme; the framework's default suffices for the management console.
- **Adapter clocks are injectable.** Tests advance time via shared `clock: () => number`. Phase 6 real adapters should accept the same option so chaos tests can simulate replication lag deterministically.
- **Refresh reuse-detection wire format.** Adapters surface `invalid_grant` with description `"... (family=<id>,tenant=<id>,subject=<id>)"`. The domain parses this for audit. This is documented as a contract in `ports/CONSISTENCY.md`-adjacent JSDoc; alternative adapters that don't follow it still produce an audit event, but with reduced fidelity (`"unknown"` placeholders). Phase 6 D1 / Postgres / DynamoDB adapters MUST follow the format.
- **State envelope ordering.** `mintStateEnvelope` serializes `{ tenantId, flowId, nonce, kid }` in that fixed order before HMAC. Same order on verify. The JSON layout is the wire format; adapters that re-serialize or normalize the envelope WILL break the MAC. Out-of-band: any future change to the envelope shape must bump a version byte.
- **`AnyAuthMethodFactory` is the public-API map type.** The strict `AuthMethodFactory<P, S, Cfg>` is for declaring individual factory exports; the variance-permissive alias is for collection types (`IdPOptions.methods`, `MethodCacheOptions.factories`). Documented in `types/method.ts`.
- **Client-secret storage is SHA-256 base64url for Phase 2.** Documented in `domain/token.ts` JSDoc. Phase 8 swaps to argon2id without changing the `ClientConfig.secretHash: string` storage shape.
- **`MethodContext.dispatch`** — populated only at `GET /authorize`. Callbacks see `null`; the flow-record fields they need are already on `ctx.flow`. Phase 4–5 method implementations should treat `dispatch === null` as the standard callback signal.

---

### Phase 3 — HTTP Adapter (Hono) ✅ **COMPLETE**

**Goal:** Thin Hono layer that parses, validates, dispatches into `domain/`, serializes results.

**Deliverables:**

- `http/router.ts` — top-level Hono app, mounts all endpoints, applies middleware.
- `http/middleware/tenant.ts` — runs `resolveTenant`, loads config from `ConfigStore` (cached), attaches `TenantContext` to Hono context.
- `http/middleware/error.ts` — catches thrown errors, maps `AuthError` → HTTP response.
- `http/middleware/audit.ts` — emits structured audit events on success / failure.
- `http/handlers/*` — one file per endpoint. Pattern:
  ```ts
  export const authorizeHandler = (idp: Domain) => async (c: Context) => {
    const parsed = v.safeParse(AuthorizeRequest, c.req.query())
    if (!parsed.success) return badRequest(c, parsed.issues)
    const result = await idp.authorize(parsed.output, c.get("tenant"))
    return result.ok
      ? renderResult(c, result.value)
      : renderError(c, result.error)
  }
  ```
- `http/schemas/*` — Zod schemas for every endpoint input.
- Integration tests: spin up the full Hono app against memory adapters, run end-to-end OAuth flow.

**Acceptance criteria:**

- All endpoints from current `issuer.ts` exist in the new layer: `/authorize`, `/token`, `/userinfo`, `/.well-known/jwks.json`, `/.well-known/oauth-authorization-server`.
- Schema validation rejects malformed input with proper OAuth error codes.
- Integration tests demonstrate parity with current `issuer.test.ts` flows.
- Hono is only imported from `http/` — `domain/` and `methods/` remain framework-agnostic. Enforced by CI lint.
- **Hand-built OAuth 2.1 + OIDC conformance matrix running on every commit.** See _Conformance scope_ below for the full Phase 3 gate (17 cases minimum). OIDF Conformance Suite explicitly deferred — not wired up in this phase or later. Coverage expands with each feature shipped (DPoP/PAR/revoke/introspect tests added in Phase 8).
- Tenant recovery chain end-to-end test: state-signed callback, partitioned-host callback, cookie fallback. Verify each path resolves the correct tenant; verify a forged state is rejected.

**Risks:**

- Cookie handling crosses domain/HTTP boundary. Mitigation: cookies live in HTTP layer; domain receives parsed values and returns "set this cookie" instructions.
- Tenant config caching can leak across tenants. Mitigation: cache is keyed by `TenantId`; invalidation hook fires on config update.

**Estimated effort:** 1 week.

#### Phase 3 — Shipped

- **`src/http/router.ts`** — single Hono app wiring: `errorMiddleware` + `bootstrapMiddleware` globally; `tenantMiddleware` on `/authorize` and `/cb/*`. Token / userinfo / revoke / introspect / well-knowns mount directly (tenant is derived from the auth-code payload or bearer claims). Hono is imported **only** from `src/http/`; `grep` confirms zero `hono` imports in `src/{types,ports,domain,adapters}/`.
- **`src/http/handlers/`** — one handler per endpoint, all thin: parse → validate (Zod) → call `domain/` → serialize.
  - `authorize.ts` — parses query against `authorizeQuerySchema`, builds an `AuthorizationRequest`, calls `startAuthorize`, and serializes the four typed outputs (`challenge`, `issue-code`, `denied`, `select-method`). Open-redirector defense: errors that fail before `redirect_uri` is validated render as plain-text 400; everything else round-trips through the RP `redirect_uri` per RFC 6749 §4.1.2.1. Method picker is a minimal `<ul>` for Phase 3; Phase 4 will fold in the themed UI under `src/ui/`.
  - `token.ts` — accepts `application/x-www-form-urlencoded` only; supports both `Authorization: Basic` and form-body client credentials (header wins); dispatches on `grant_type` to `exchangeCode` / `refreshTokens`. Schema parse failures on `grant_type` map to `unsupported_grant_type` (RFC 6749 §5.2).
  - `callback.ts` — delegates to `handleCallback`. Returns plain text on `denied` because the flow record has been consumed and the RP redirect URI is no longer in scope.
  - `userinfo.ts` — RFC 6750 bearer extraction, returns 401 + `WWW-Authenticate: Bearer` on invalid token per OIDC Core §5.3.
  - `metadata.ts` — `/.well-known/openid-configuration` (also served at `/.well-known/oauth-authorization-server`) and `/.well-known/jwks.json`. Both advertise `Cache-Control: public, max-age=60`.
  - `revocation.ts` — RFC 7009 `/revoke` (always 200 per §2.2 even on unknown token) and RFC 7662 `/introspect`.
- **`src/http/middleware/`**
  - `bootstrapMiddleware` — parses the `Cookie:` header into a read-only `Map<string, string>` and resolves the per-request issuer URL.
  - `tenantMiddleware` — runs the callback recovery chain (Phase 3 ships the `mac-state` path; `host-plus-*` and `flowId-in-uri` mechanisms are scaffolded but punt to `resolveTenant`, see _Deferred_). On non-callback paths calls `IdPOptions.resolveTenant`, loads `TenantConfig` from `ConfigStore`, and attaches a `TenantContext`. On `/authorize` failures it emits plain-text 400 (open-redirector defense); on token-style endpoints it emits the standard OAuth JSON shape.
  - `errorMiddleware` — last-resort `try/catch` that wraps unexpected throws into `server_error` JSON. Domain functions never throw across the boundary; this is the net for runtime bugs.
- **`src/http/cookies.ts`** — framework-owned cookie policy.
  - `parseCookieHeader` — tolerant `Cookie:` parser, returns `Map`.
  - `serializeSetCookie` — renders `SetCookie` data through framework policy: `Secure` forced on by default, `SameSite=Lax` default, `HttpOnly` defaulted to true for any cookie name in the `auth.*` / `idp.*` reserved namespace.
  - `applyResponsePolicy` — sanitization helper. Strips `Set-Cookie`, security headers, and `Cache-Control` from any method-returned `Response`, then merges in framework-controlled `Set-Cookie` headers and a `Cache-Control` value (defaults to `no-store`; methods opt in via the typed `CachePolicy` field).
- **`src/http/errors.ts`** — `AuthError` → HTTP. Two surfaces: token-style endpoints (`{ error, error_description }` JSON with RFC-correct status — `invalid_client` → 401 + `WWW-Authenticate`, server-side → 500, others → 400) and `/authorize` (302 to `appRedirectUri` per RFC 6749 §4.1.2.1 OR plain-text fallback for `isNonRecoverable` errors). `publicErrorCode` rewrites framework-internal codes (`internal_error` → `server_error`, `method_not_found` / `tenant_not_found` / `unknown_state` → `invalid_request`) before they touch the wire.
- **`src/http/schemas/`** — Zod schemas for every endpoint input. `authorizeQuerySchema` (with passthrough so we don't accidentally drop standard OIDC params), `tokenRequestSchema` (discriminated union on `grant_type`), `revokeBodySchema` / `introspectBodySchema`.
- **`src/index.ts`** — `createIdP` is no longer a stub. Wiring:
  1. Validates the factory-map invariant (`Object.keys(opts.methods)[i] === opts.methods[k].kind` for every entry) and throws with a list of offenders on disagreement.
  2. Builds a `MethodCache` over the factory map.
  3. Composes an `HttpDeps` record and hands it to `buildRouter`.
  4. Returns an `IdP` whose `handle` / `authorize` / `token` / etc. all bottom out at `app.fetch(req)` — the per-endpoint primitives re-enter the same Hono app, which already path-dispatches.
- **Conformance — 17 hand-built cases under `test/conformance/oauth-2.1.test.ts`** matching the §"Conformance scope" matrix one-for-one:
  1. `/authorize` happy path with PKCE → 302 to upstream with valid state.
  2. `/authorize` missing required params → 400 `invalid_request`.
  3. `/authorize` with `response_type=token` → rejected (OAuth 2.1 is code-only).
  4. `/token` with valid code + verifier → access + refresh issued.
  5. `/token` with already-consumed code → `invalid_grant`.
  6. `/token` with expired code → `invalid_grant`.
  7. `/token` with reused code → `invalid_grant`.
  8. PKCE: missing `code_verifier` → `invalid_grant`.
  9. PKCE: wrong `code_verifier` → `invalid_grant`.
  10. PKCE: correct `code_verifier` → success.
  11. Refresh with valid token → new tokens + old marked revoked.
  12. Refresh reuse detection → `invalid_grant` + `refresh_reuse_detected` audit + downstream family token revoked.
  13. `/.well-known/openid-configuration` → discovery doc shape (issuer, endpoints, `response_types: ["code"]`, `code_challenge_methods: ["S256"]`).
  14. `/.well-known/jwks.json` → keys array with `kid` / `alg` / `use: "sig"`.
  15. State MAC: invalid state on callback → 400 + `flow_replay_attempt` audit.
  16. State MAC: forged envelope claiming wrong tenant for a real flowId → 400 + `flow_tenant_mismatch` audit.
  17. Two-tenant isolation: cross-tenant client cannot consume a code minted for another tenant.
- **Test harness** — `test/helpers/idp.ts` (`buildHarness`, `authorizeUrl`, `tokenRequest`, `driveCallback`) centralizes the boilerplate so each case stays short.
- **Verification gates passed:**
  - `bunx tsc --noEmit -p tsconfig.json` exits 0 under `strict: true`.
  - `bun test` — **168/168** green (67 legacy + 84 Phase 2 + 17 conformance).
  - `grep` confirms `hono` is imported only from `src/http/`; no `node:*` imports in `src/{types,ports,domain,adapters}/`.

#### Phase 3 — Deferred

- **Tenant recovery mechanisms #2 (partitioned host) and #3 (`flowId`-in-URI).** The middleware is shaped to dispatch on the full `TenantRecovery` union and the `mac-state` path is fully wired. The host-plus-mac / host-plus-uri / flow-id-in-uri paths need (a) a reverse host→tenant index that the public `callbackHostFor: (tenantId) => string` API does not expose, and (b) registered-redirect-URI templates that match flow-id-in-URI segments. Both are pluggable inside a user-supplied `resolveTenant` today; framework-owned plumbing lands when an actual user requests it. **Plan §"Phase 2 — Deferred" already flagged this for Phase 3**; we keep it deferred because the 17-case gate doesn't require it and the scaffolding (`TenantRecovery` type, `FlowRecord.callbackHost`/`callbackPath` fields) is in place.
- **Method route mount (`/m/<methodId>/<subPath>`).** Methods that declare custom routes beyond `GET /authorize` and `GET /callback` (e.g. password's `POST /login`, passkey's `POST /authenticate-verify`) need a URL surface. Phase 3's stub method factories don't exercise this, and `dispatchMethod` already centralizes the call. The thin Hono route lands with Phase 4 when there's a real consumer.
- **CI lint job** — the "no `hono` outside `src/http/`" rule is still verified by `grep` locally. The GitHub Action is a one-line addition; it lands in Phase 4 / Phase 5 alongside the `methods/` import rule (methods cannot import `hono`).
- **`isErr` rename / cleanup of `tokenEndpointErrorResponse` 500-path detail.** The `server_error` path returns the bare `error_description`; richer cause propagation (and Sentry/OTEL integration) waits for Phase 8 structured logging.
- **CORS middleware.** The plan lists a placeholder; per-client CORS allowlists land with `ClientConfig.corsOrigins` in Phase 7 / Phase 8 (depending on console requirements). For Phase 3 the `Access-Control-*` headers can be added by an outer reverse-proxy layer.

#### Phase 3 — Decisions captured for later phases

- **`/authorize` open-redirector defense is the boundary.** Any error that occurs before the framework has verified `redirect_uri` against `ClientConfig.redirectUris` MUST render plain-text 400, not a 302. `isNonRecoverable(error)` is the single chokepoint (`http/errors.ts`): unknown client, tenant not found, method not found, and `invalid_request` with `field === "redirect_uri"`. Phase 4–8 must extend this set if they introduce new pre-redirect failure modes (e.g. PAR `request_uri` lookup miss).
- **Cookie sanitization is enforced on every method-returned `Response`.** `applyResponsePolicy` strips a fixed allowlist of headers (`Set-Cookie` variants, security headers, `Cache-Control`) before merging in framework `Set-Cookie[]` data and the framework's chosen `Cache-Control`. Methods cannot bypass this short of importing `cookie` or `set-cookie-parser` directly — Phase 4 lint catches that at build time.
- **`createIdP` factory-map invariant is enforced at construction.** `Object.keys(opts.methods)[i] === opts.methods[k].kind`; mismatches throw with a descriptive list. Future docs and the management console (Phase 7) should make the key explicit so users never type the same string twice.
- **Token endpoint never runs the tenant middleware.** Tenancy is derived from the auth-code payload (or the refresh token's payload). Phase 6 adapters must therefore not assume `c.get("tenant")` exists in the token-endpoint codepath — relevant to anyone porting middleware later.
- **Hono is reversible.** Per AD3, the framework dependency on Hono lives entirely under `src/http/`. The `HttpDeps` / `HttpVars` types are framework-neutral; only `router.ts`, `context.ts`, and the middleware files import from `hono`. Rewriting to another router would re-write those three files plus the handler `(c) => Response` signatures.
- **Issuer URL is per-request.** `IdPOptions.issuerUrl` may be a function; `bootstrapMiddleware` resolves it once and stamps `HttpVars.issuerUrl`. Discovery, JWTs, and userinfo all read from this resolved value. Multi-tenant deployments that vary issuer by host get this for free.
- **`SetCookie.value: null` clears (`Max-Age=0`).** Documented on the type; the cookie serializer honors it. Phase 4 methods that log a user out should rely on this rather than empty-string values.

##### Open items surfaced during Phase 3

- The `callbackHostFor` API is forward-only (`tenantId → host`). The recovery chain needs the inverse to identify a tenant from an inbound request host. Two clean options: (a) require an inverse map alongside (`hostToTenant: Map<host, tenantId>` derived at construction); (b) let users encode the inverse inside their own `resolveTenant`. Option (b) is the current implementation; option (a) becomes attractive in Phase 7 when the console wires up per-tenant subdomains.
- `StartAuthorizeDeps.callbackHostFor` is typed `(tenantId: string) => string` while `IdPOptions.callbackHostFor` is `(tenantId: TenantId) => string`. Phase 3 bridges with a cast at the call site. Phase 6 should tighten the `domain/authorize` type to `TenantId` for consistency; no behavior change.

---

### Phase 4 — Credential & WebAuthn Methods ✅ **COMPLETE**

**Goal:** Implement non-redirect auth methods. Prove the `AuthMethod` abstraction with the four hardest cases.

**Deliverables:**

- `methods/password.ts` — argon2id by default (drop bcrypt). Routes: `GET /authorize` (render form), `POST /login`, `POST /register`, `POST /forgot`, `POST /reset`. Configurable via `passwordMethod({ hash, validate, ...hooks })`.
- `methods/code.ts` — magic code (email/SMS). Routes: `GET /authorize` (render request form), `POST /send`, `POST /verify`. Configurable sender (`sendCode: async (to, code) => {...}`).
- `methods/m2m.ts` — client credentials grant. Just a `client` fn; no routes (handled at `/token`).
- `methods/passkey.ts` — WebAuthn. Routes: `GET /authorize`, `POST /authenticate-options`, `POST /authenticate-verify`, `POST /register-request`, `POST /register-verify`. Use `@simplewebauthn/server`.
- UI components under `ui/` for each method.
- Tests per method using memory adapters + simulated requests.

**Acceptance criteria:**

- Each method implemented as a single file exporting an `AuthMethod` (no Hono mounts).
- End-to-end test for each: configure, attempt auth, receive `success` MethodResult, framework issues tokens.
- Passkey works with a real WebAuthn ceremony in a browser (manual test, automated test if feasible).
- Password storage uses argon2id (configurable). Existing scrypt/bcrypt paths gone.

**Risks:**

- WebAuthn complexity. Mitigation: `@simplewebauthn/server` handles the heavy lifting; we just wire it into `AuthMethod`.
- Email/SMS sender abstraction. Mitigation: it's a function the user supplies; we don't build email infra.

**Estimated effort:** 2 weeks.

#### Phase 4 — Shipped

- **The third pipeline.** `domain/method-route.ts` (`handleMethodRoute`) orchestrates credential POSTs: read flow cookie → peek `readFlow` → dispatch the method's `POST <subPath>` (or `GET <subPath>`) → translate `MethodResult` (challenge updates `methodState`; success consumes the flow and snapshots into an auth code). Mounted at `/m/:methodId/*` by `http/handlers/method-route.ts` and `http/router.ts`. The HTTP authorize handler now stamps an HttpOnly `idp.flow=<flowId>` cookie on every `challenge` response so credential POSTs identify the in-flight flow without trusting form input; the cookie is cleared on `issue-code` / `denied`.
- **`SessionStore.readFlow`** — new port method (peek without consume). The Phase 2 `consumeFlow` stays single-use; `readFlow` lets multi-step methods (`/send` → `/verify`, register-options → register-verify) re-enter the flow record without burning it. The in-memory adapter implements it atomically.
- **`AuthorizeOutput.challenge.flowId`** — domain `startAuthorize` now exposes the flowId on its challenge output so the HTTP layer can stamp the framework cookie.
- **`domain/password-hash.ts`** — pluggable `PasswordHasher` interface (`hash` / `verify`) with an argon2id default (`@noble/hashes/argon2`). Output is canonical PHC string (`$argon2id$v=19$m=N,t=N,p=N$<salt>$<hash>`). Defaults follow RFC 9106 §4 (t=3, m=64 MiB, p=4). Pure JS — edge compatible, no native deps.
- **`methods/password.ts`** — `passwordMethod({ users, hasher?, enableRegistration?, title? })`. Routes: `GET /authorize` (login form), `POST /login` (verify credentials), `POST /register` (gated by `enableRegistration` flag). The framework does NOT own the user record; tenants supply a `PasswordUserStore` (`findByEmail` + optional `create`). Hashes ride on `PasswordUser.passwordHash`. Re-renders the form with `methodState.error` after a failed attempt.
- **`methods/code.ts`** — `codeMethod({ sendCode, destinationKind?, maxAttempts?, generateCode? })`. Routes: `GET /authorize` (destination form), `POST /send` (mint 6-digit code, call `sendCode` hook, render verify form, stash SHA-256 hash in `methodState`), `POST /verify` (compare timing-safe, increment attempts, deny after `maxAttempts`). Anti-enumeration: `/send` always renders the verify form whether or not the destination resolved.
- **`methods/m2m.ts`** — `m2mMethod({ verify })`. No URL routes; only a `client` fn. The factory exposes the user's `verify` hook (called AFTER the framework has authenticated `client_id`/`client_secret`) so tenants attach claims and decide whether the (already-authenticated) client may use this method.
- **`domain/client-credentials.ts`** — `clientCredentialsGrant`. New domain function for RFC 6749 §4.4: authenticates the client (must be confidential + grantTypes includes `client_credentials`), validates scope subset, resolves the tenant's unique enabled `type: "m2m"` method instance (0 or >1 → error), calls `method.client(...)`, runs the user's `success` callback, mints access token. Per §4.4.3 the response strips `refresh_token`.
- **`/token` accepts `client_credentials`.** Schema extended with `clientCredentialsGrantSchema` (discriminated union); the HTTP handler resolves tenant via `IdPOptions.resolveTenant` against the raw `/token` request, then delegates to `clientCredentialsGrant`.
- **`methods/passkey.ts`** — `passkeyMethod({ rpName, rpID, origin, credentials, title? })`. Routes: `GET /authorize` (username form), `POST /authenticate-options` (mint `PublicKeyCredentialRequestOptionsJSON`, stash challenge in `methodState`), `POST /authenticate-verify` (verify assertion, update counter, return success), `POST /register-options` + `POST /register-verify` (gated by `credentials.create`). Wraps `@simplewebauthn/server` directly; transports / counter / public key persist via the user-supplied `PasskeyCredentialStore`.
- **`ui/forms.ts`** — minimal zero-JS HTML form helpers (`htmlPage`, `renderForm`, `escapeHtml`) shared by `password` and `code`. Dark-mode aware via `color-scheme` + `prefers-color-scheme`. Theming + richer customization land in later phases.
- **Public API exports.** `passwordMethod`, `codeMethod`, `m2mMethod`, `passkeyMethod`, `argon2idHasher`, `DEFAULT_ARGON2ID_PARAMS`, and supporting types are now exported from `src/index.ts`.
- **Tests (12 new across 5 files, 180 total):**
  - `test/methods/password.test.ts` — end-to-end happy path (form render → login → token) + wrong-password re-renders error.
  - `test/methods/code.test.ts` — end-to-end (deterministic code via `generateCode` override, captured deliveries via `sendCode`, wrong code → 400, correct code → 302 → /token success).
  - `test/methods/m2m.test.ts` — happy path (client_credentials → access token, no refresh, scope honored) + unauthorized client (no `client_credentials` in grantTypes → `unauthorized_client`).
  - `test/methods/passkey.test.ts` — shape coverage: form render on `/authorize`, JSON challenge minting on `/authenticate-options` for known users. Full ceremony is a manual / Phase 7 console test; see Deferred.
  - `test/methods/password-hash.test.ts` — argon2id round-trip, wrong-password rejection, malformed PHC rejection, non-argon2id algorithm rejection, salt uniqueness.
- **Verification gates passed:**
  - `bunx tsc --noEmit -p tsconfig.json` exits 0 under `strict: true`.
  - `bun test` — 180/180 green (168 Phase 1-3 + 12 Phase 4).
  - `grep` confirms zero `hono` / `node:*` imports in `src/{types,ports,domain,adapters,methods}/`.
  - All 17 OAuth 2.1 + OIDC conformance cases remain green — Phase 4 is additive.

#### Phase 4 — Deferred

- **Password forgot / reset routes.** `POST /forgot` and `POST /reset` need the same `sendCode`-style hook the magic-code method uses. They land in Phase 5 alongside email-sender infrastructure (the OAuth/OIDC migration touches the same hook plumbing for emails like "your <provider> account was linked").
- **Full WebAuthn ceremony in CI.** Phase 4 ships shape coverage (form render, options minting, error paths) but a real authenticator → verify roundtrip requires either a simulated authenticator harness (e.g. `@simplewebauthn/server` test fixtures) or a real browser. The plan §"Acceptance criteria" calls out "manual test, automated test if feasible"; the management console (Phase 7) is the natural home for the automated end-to-end since it has a real browser context.
- **Multi-domain passkey RPs.** Per-factory `rpID` works; tenants with multiple RP domains today instantiate multiple factories. A single-method-multi-domain model lands if a real customer needs it.
- **Argon2id parameter migrations.** `verify()` accepts arbitrary `t` / `m` / `p` parameters from the stored hash (so legacy hashes continue to verify). A `needsRehash` helper that flags weak parameters and a transparent rehash-on-login path are not yet implemented; the standard pattern is "rehash inside the user's `success` callback when `passwordHash` is below current strength."
- **Rate limiting on `/m/*`.** Phase 8 brings the cross-cutting rate-limiter port; Phase 4 leans on `codeMethod.maxAttempts` for the most obvious lockout and on the framework's own flow TTL for general bounding.

#### Phase 4 — Decisions captured for later phases

- **`idp.flow` cookie is the credential-flow identity token.** HttpOnly, SameSite=Lax, framework-owned. Methods cannot read or write it directly. Set on every `/authorize` challenge; cleared on `issue-code` / `denied`. Phase 8 may upgrade to a CSRF token bound to the cookie for additional defense — the cookie alone is sufficient against most CSRF when paired with SameSite=Lax.
- **`SessionStore.readFlow` is a peek primitive.** Production adapters (Phase 6 D1 / Postgres / DynamoDB) implement it as a plain read; the consume operation remains the single CAS chokepoint. Adapters MUST guarantee that `consumeFlow` racing with `readFlow` resolves so the consume wins or sees a CAS miss — a record visible to `readFlow` must either still be consumable or yield `unknown_state`.
- **The user-supplied `users` / `credentials` store is the trust boundary.** Methods never touch storage adapters directly — the tenant supplies a typed store interface that the method calls. This keeps the framework's storage ports (`TokenStore` / `SessionStore` / `KeyStore`) separate from application data (users, passkey credentials) and lets the management console (Phase 7) reuse those stores without going through the IdP.
- **m2m method dispatch is "unique enabled instance per tenant."** Phase 4 rejects requests when 0 or >1 m2m methods are configured. If a real customer needs multiple m2m flavours (e.g. different scope policies per service tier), `ClientConfig.methodId` becomes the binding key — but that's a schema change deferred until needed.
- **`@noble/hashes` is the canonical pure-JS crypto dependency.** Phase 4 added argon2id; future phases that need a similar pure-JS, edge-compatible primitive (e.g. scrypt for legacy migration, HKDF for key derivation) should prefer this package over native modules.
- **`AuthMethod.routes` keys are `"<METHOD> <subPath>"`.** Verbatim from the type contract since Phase 1; Phase 4 establishes the per-method conventions for the bundled methods (`POST /login`, `POST /send` etc.) and the URL surface they expose under `/m/<methodId>/*`. Phase 5 OAuth/OIDC methods only need `GET /authorize` + `GET /callback` and stay off the `/m/*` mount.
- **Password / code use empty `configSchema`.** The tenant doesn't supply config — users, send hooks, etc. live on the factory closure. Other approaches (per-tenant template overrides, per-tenant `sendCode` URLs) are explicit factory options when needed; we don't push them through `MethodConfig.config` because that blob is for things that change without re-instantiating the factory.

##### Open items surfaced during Phase 4

- The `clientCredentialsGrant` function casts `tenantId: string` to `TenantId` at the port boundary (`getTenantConfig(tenantId as never)`). Same kind of cast as `startAuthorize.callbackHostFor` — Phase 6 tighten-up.
- `M2MMethodOptions.verify` does not return scopes/audience; per-client scope decisions still rely on `ClientConfig.scopes`. A richer return shape (`{ allowedScopes, audience, claims }`) is straightforward to add later without breaking callers.
- The form helpers in `ui/forms.ts` are inline strings. A JSX-flavored UI lives in `src/ui/` for the legacy implementation. Reconciling those (or migrating the bundled methods to JSX) is a Phase 5 / Phase 7 cleanup.

---

### Phase 5 — OAuth/OIDC Provider Family (All Existing Providers) ✅ **COMPLETE**

**Goal:** Port all 15 OAuth/OIDC providers (+ generic `oauth2`/`oidc` building blocks + `arctic` wrapper) to the new model. Validate that the generic methods are reusable.

**Deliverables:**

- `methods/oauth2-generic.ts` — base OAuth 2.0 method. Routes: `GET /authorize` (redirect to upstream), `GET /callback` (exchange code, fetch user info). Parameterized by:
  ```ts
  oauth2Method({
    authorizeUrl, tokenUrl, userInfoUrl,
    scopes, mapClaims, fetchUserInfo?, ...
  })
  ```
- `methods/oidc-generic.ts` — extends `oauth2-generic` with ID token validation, discovery doc fetching, JWKS rotation. Uses `jose`.
- `methods/providers/` — one wrapper per existing provider. Each is ~5-30 lines:
  ```ts
  // methods/providers/google.ts
  // Provider exports are AuthMethodFactory instances, not pre-built AuthMethods.
  // Registered globally in createIdP; each tenant provides its own credentials via MethodConfig.config.
  export const googleFactory: AuthMethodFactory<
    GoogleProperties,
    GoogleState,
    GoogleConfig
  > = {
    kind: "google",
    configSchema: z.object({
      clientId: z.string(),
      clientSecret: z.string(),
      scopes: z.array(z.string()).default(["openid", "email", "profile"]),
      hostedDomain: z.string().optional(),
    }),
    build: async ({ id, kind, tenantId, config }) =>
      oidcGenericMethod({
        id, // tenant-local instance id from MethodConfig.id
        kind, // factory kind from MethodConfig.kind
        issuer: "https://accounts.google.com",
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        scopes: config.scopes,
        extraAuthParams: config.hostedDomain
          ? { hd: config.hostedDomain }
          : undefined,
      }),
  }
  ```
  Then in `createIdP({...})`: `methods: { google: googleFactory, github: githubFactory, ... }`. Tenants reference factories by `MethodConfig.kind: "google"`.
- Port: google, github, apple, discord, facebook, linkedin, microsoft, slack, spotify, twitch, x, yahoo, jumpcloud, keycloak, cognito.
- Port: `arctic.ts` — wrap the Arctic library if we keep it; otherwise drop.
- Tests: each provider configured in a fake setup, mock the upstream, run full redirect → callback → tokens flow.

**Acceptance criteria:**

- All 15 OAuth/OIDC providers ported with parity to current behavior. `oauth2-generic` and `oidc-generic` cover ≥80% of provider code.
- Each provider wrapper is small (target: <40 lines).
- A single matrix integration test runs the redirect flow for every provider against a mock upstream.
- Discovery doc auto-fetched for OIDC providers (Google, Apple, Microsoft, Keycloak, JumpCloud, Cognito); avoids stale config.
- `oauth4webapi` (per AD7b) is used inside `oauth2-generic` / `oidc-generic` for the outgoing client side (request construction, response parsing, JWKS validation). Per-provider files only override what's quirky.

**Risks:**

- Provider quirks (Apple's form_post response mode, Microsoft's tenant-specific endpoints, etc.). Mitigation: each provider can override hooks (`buildAuthorizeUrl`, `parseCallback`, `fetchUserInfo`); base methods expose extension points.
- Refresh token handling varies wildly across providers. Mitigation: capture upstream refresh tokens in `properties`; let the user's `success` hook decide what to do.

**Estimated effort:** 1.5-2 weeks (most providers are 10-30 minutes each once oauth2-generic + oidc-generic are solid).

#### Phase 5 — Shipped

- **`methods/oauth2-generic.ts` (`buildOauth2Method`)** — the workhorse for every redirect-style provider. Routes:
  - `GET /authorize` — builds the upstream redirect with `client_id`, `redirect_uri = dispatch.callbackUrl`, `response_type=code`, `state = dispatch.state` (the framework's MAC envelope), `scope`, optional PKCE (`S256` default; `pkce: "none"` opt-out for upstreams that don't accept it), and any provider-specific extra query params. PKCE verifier is stashed in `methodState`.
  - `GET /callback` — exchanges the auth code at `tokenUrl`, optionally verifies the returned `id_token` against `jwksUri` (via `jose.createRemoteJWKSet` + `jwtVerify` with audience + expected issuer), and returns the standard `Oauth2Properties` shape (`tokens.{access,refresh,expiresIn,idToken}` + decoded `idTokenClaims` + raw token-endpoint response).
  - `POST /callback` — same as GET, conditionally mounted when `responseMode: "form_post"` (Apple). The HTTP layer now accepts POST on `/cb/*` and the tenant middleware extracts `state` from the form body for `form_post`.
  - `defaultDeriveSubject` walks `idTokenClaims.sub` → `raw.sub` → `raw.user_id` → `raw.id`; pluggable for providers that compute the subject differently.
- **`methods/oidc-generic.ts` (`buildOidcMethod`)** — thin layer over `buildOauth2Method`. Fetches `/.well-known/openid-configuration` from the configured `issuer` at factory-build time and plumbs `authorization_endpoint` / `token_endpoint` / `jwks_uri` into the underlying OAuth method. The `MethodCache` caches the built method per `(tenantId, MethodConfig.id)` so discovery is one HTTP round trip per tenant config invalidation. Providers with non-standard discovery (Cognito) pass `endpoints` directly to bypass auto-fetch.
- **15 provider factories under `methods/providers/`** — each ~35-55 lines, all `<AuthMethodFactory>` exports with a `kind` matching the file name and a Zod `configSchema` for tenant-supplied credentials. Endpoint URLs and defaults baked into the wrapper; the generic methods own all the logic.
  - OIDC (auto-discovery): `google`, `apple`, `microsoft` (tenant-templated), `slack` (Sign in with Slack), `yahoo`, `jumpcloud`, `keycloak` (per-realm), `cognito` (explicit endpoints).
  - OAuth 2.0 (no id_token by default): `github` (PKCE off — GitHub doesn't accept it), `discord`, `facebook` (with `useOidc: true` switch), `linkedin`, `spotify`, `twitch`, `x` (PKCE required), `yahoo` (OIDC).
  - Total wrapper LOC ~600 vs ~345 in the two generics — by LOC the generics are ~57%, but by logic ALL of the OAuth/OIDC ceremony lives in the generics (the wrappers only declare config schemas + endpoint URLs).
- **`POST /cb/*` support.** Apple `response_mode=form_post` now works end-to-end: the router mounts both GET and POST on `/cb/*`; the tenant middleware reads `state` from query OR form body (via `req.clone()` so the handler can still read the body); `buildOauth2Method`'s callback handler does the same for `code`.
- **`oauth4webapi` dependency** — added per AD7b. Used for PKCE primitives (`generateRandomCodeVerifier`, `calculatePKCECodeChallenge`). The token-exchange dance and id_token validation stay on plain `fetch` + `jose` because per-provider quirks make oauth4webapi's strict `AuthorizationServer` shape more friction than help; the door is open to migrate fully when a real customer benefits.
- **Public API exports** — `buildOauth2Method`, `buildOidcMethod`, all 15 `*Factory` exports, plus `Oauth2Properties` / `Oauth2State` / `Oauth2MethodInput` / `OidcMethodInput` types.
- **15-case provider matrix test** at `test/methods/providers.test.ts`. One parameterized case per provider:
  1. Configure a tenant with that provider as the sole enabled method.
  2. Run `/authorize` and assert the redirect lands on the expected upstream host with the framework state, configured `client_id`, and `response_type=code`.
  3. Simulate the upstream callback (`/cb/<methodId>?state=…&code=upstream-code`) and assert the framework mints an auth code and redirects back to the RP.
  4. Exchange the auth code at `/token` and assert tokens are issued.

  Global `fetch` is monkey-patched for the test file so discovery docs + token endpoints return deterministic JSON; `afterAll` restores the original. The mock does NOT issue real id_tokens — full id_token-verification coverage needs a real signed JWT + matching JWKS, deferred to integration tests against real upstreams (or fixture-based tests in Phase 8 hardening).
- **Verification gates passed:**
  - `bunx tsc --noEmit -p tsconfig.json` exits 0 under `strict`.
  - `bun test` — **195/195** green (180 prior + 15 provider matrix).
  - `grep` confirms zero `hono` / `node:*` imports in `src/{types,ports,domain,adapters,methods}/`.
  - All 17 OAuth 2.1 conformance cases still green; method-route + credential + provider tests still green.

#### Phase 5 — Deferred

- **`arctic` wrapper.** The legacy `provider/arctic.ts` wraps the [Arctic](https://arcticjs.dev) library to lean on its per-provider endpoint constants. The new `buildOauth2Method` already absorbs that role (endpoint URLs are baked into each `methods/providers/*.ts` wrapper), so the Arctic wrapper is dropped per the plan's "or drop" branch. Anyone who needs Arctic-specific behavior can call `buildOauth2Method` directly with Arctic's endpoint constants.
- **Full id_token verification in CI.** The matrix test stubs `fetch` so the upstream returns `access_token` + `sub` directly. For OIDC providers the framework would normally verify the `id_token` against the JWKS; CI coverage of that path needs a real signed JWT + matching JWKS or a per-provider stub keystore. Phase 8 hardening adds either real-network nightly integration tests or fixture-based ceremonies, whichever lands faster.
- **`oauth4webapi` deeper integration.** Phase 5 uses it only for PKCE; the token-exchange + id_token-validate flow uses plain `fetch` + `jose`. Migrating to `oauth4webapi`'s `authorizationCodeGrantRequest` / `processAuthorizationCodeResponse` is a clean cleanup but requires reshaping config into `AuthorizationServer` + `Client` + `ClientAuth` objects. Defer until a provider-quirk crisis forces it.
- **Refresh-token rotation for upstream providers.** The framework's own refresh-token rotation (Phase 2) is unchanged; upstream refresh tokens captured in `properties.tokens.refresh` are stored by the user's `success` callback (or via `IdPOptions.persistUpstreamTokens`). A first-class "refresh upstream tokens" facility lives at the application layer, not in the IdP — same as the legacy provider design.
- **Provider-specific tests against real upstreams.** The plan's acceptance criterion ("each provider configured in a fake setup, mock the upstream, run full redirect → callback → tokens flow") is satisfied by the matrix test. Real-network smoke tests are an operational concern (private credentials, flakiness) and live in deployment runbooks, not the package suite.

#### Phase 5 — Decisions captured for later phases

- **`buildOauth2Method` is the public API for custom providers.** Users with a provider we haven't pre-wrapped (legacy ADFS, OneLogin, in-house OAuth server, etc.) can wire their own `AuthMethodFactory` whose `build` calls `buildOauth2Method` or `buildOidcMethod`. No internal-only escape hatch; the same path the bundled providers use is the customer-facing one.
- **Provider wrappers stay tiny by contract.** Each wrapper is *only* a `kind` constant, a `configSchema`, and a `build` that calls the generic with the right URLs. Provider-specific custom logic (overriding `deriveSubject`, fetching userinfo, mapping claims) is allowed but rare; if a wrapper grows past ~50 lines it's a signal that the generic should learn a new hook.
- **The `idp.flow` cookie is set on every challenge** — including upstream-redirect challenges. This means the cookie is in flight while the user is at the upstream provider; on callback the framework recovers via the state envelope (primary) and the cookie is available as defense-in-depth for the `flowId`-in-URI recovery path when it lands.
- **`POST /cb/*` requires body cloning in the tenant middleware.** The middleware uses `req.clone().text()` for `form_post` callbacks so the handler can still read the body. Adapter authors building bespoke routers must preserve this — cloning is cheap (the body's bytes haven't been read yet) and indispensable for Apple support.
- **`expectedIssuer` on the OAuth2 generic is the wire-format issuer**, not the configured `issuer` parameter. For Microsoft this matters: the user passes `tenant: "common"` and the framework builds `issuer = https://login.microsoftonline.com/common/v2.0`, but Microsoft's id_tokens carry a *tenant-specific* `iss` claim (the resolved tenant). `buildOidcMethod` uses `endpoints.issuer` (from discovery) as `expectedIssuer`, which Microsoft's discovery doc fills in correctly.
- **OIDC method state has no upstream-nonce.** Phase 2's plan §"Two PKCEs, never confuse them" mentions OIDC providers stashing `upstreamNonce`. Phase 5 doesn't currently use `nonce` for OIDC providers; relying on PKCE + state-MAC is sufficient for the auth-code flow against the existing 15 providers. Adding `nonce` is a one-line addition to `buildOauth2Method` if a future provider requires it.

##### Open items surfaced during Phase 5

- The matrix test's mock fetch is per-file. If multiple test files want fetch-level mocking, we'll factor it into a `test/helpers/mock-fetch.ts`. Phase 6 storage tests against real backends (D1, Postgres) won't need it.
- Provider OIDC discovery cache is per `MethodCache` entry; it lives as long as the tenant config does. Phase 6's `ConfigStore.onInvalidate` hook will need to wire into the cache so a tenant config update forces re-discovery — currently invalidation is manual (`MethodCache.invalidate(tenantId)`). Tracked for Phase 6.

---

### Phase 6 — Real Storage Adapters

**Goal:** Replace memory adapters with production-grade storage.

**Deliverables:**

- `adapters/d1/` — Cloudflare D1 (SQL) for ConfigStore + TokenStore + SessionStore + KeyStore. **D1 caveat:** D1 supports read replicas with asynchronous replication. All token/code/flow operations (the security-critical paths) MUST use the **D1 Sessions API with bookmarks** (or primary-pinned reads) to guarantee read-after-write consistency. The adapter is certified only when its tests demonstrate: (a) `consumeCode`/`consumeFlow` immediately after the corresponding `saveCode`/`saveFlow` return the row, even under simulated replication lag; (b) `consumeRefresh` CAS resolves to exactly one winner under concurrent attempts; (c) `revokeBySubject` propagates within the documented SLA. Source: <https://developers.cloudflare.com/d1/best-practices/read-replication/>. Read-eventual paths (`ConfigStore.getTenantConfig`, JWKS) may use replicas freely.
- `adapters/durable-object/` — Cloudflare Durable Objects for SessionStore (flow records) and optionally TokenStore in deployments without D1.
- `adapters/kv/` — Cloudflare KV. **Restricted use only:** cacheable tenant config (with TTL), JWKS read cache, and other non-security-critical read-heavy data. **Must not** back TokenStore code/refresh methods or SessionStore flow records — KV's eventual consistency violates the contracts in _Port Consistency Requirements_.
- `adapters/dynamo/` — DynamoDB for ConfigStore + TokenStore (AWS Lambda use case).
- `adapters/postgres/` — Postgres for Node deployments.
- `adapters/kms/` — AWS KMS / Cloudflare DO for KeyStore (encryption keys, signing keys).
- Migration files for D1 + Postgres (SQL schema).
- Integration tests against each adapter (use ephemeral DB / mocked DynamoDB / etc.).
- Documentation: "deploying to Cloudflare", "deploying to AWS Lambda", "deploying to Node + Postgres."

**Acceptance criteria:**

- Each adapter passes the same integration test suite (parameterized).
- Performance benchmark: authorize → token round trip <100ms on each platform (Cloudflare, AWS, Node).
- Adapters expose health checks: `await adapter.ping()` for liveness probes.

**Risks:**

- Per-platform quirks (DynamoDB single-table design, D1 SQLite limitations, KV eventual consistency). Mitigation: each adapter has its own design doc; tests run against real (or close to real) backends.

**Estimated effort:** 2-3 weeks.

---

### Phase 7 — Management Console

**Goal:** Build the IdP's own management console as a real OAuth client of the IdP. Eat the dogfood.

**Deliverables:**

- `apps/console/` — Next.js (or Astro, or SvelteKit) app. Pick once.
- Auth flow:
  - Reserved "system" tenant configured in the IdP.
  - Console registered as an OAuth client of the system tenant.
  - Admin login: passkey + magic code (no public OAuth providers in system tenant).
  - Console uses the access token to call its own admin API.
- Console features (MVP):
  - List tenants.
  - Create / edit tenant (basic config — name, theme, cookie domain).
  - Per-tenant: list / create / edit / disable clients.
  - Per-tenant: list / configure auth methods (enable Google, set OAuth credentials, etc.).
  - Per-tenant: view audit log.
  - Self-service admin management (invite / remove admins).
- Admin API endpoints in the IdP (separate from OAuth endpoints):
  - `GET /admin/tenants`, `POST /admin/tenants`, ...
  - Guarded by access token with `admin:*` scope, only issuable from system tenant.
- Audit log entries for all admin actions.

**Acceptance criteria:**

- Admin can sign up for system tenant, log in via passkey.
- Admin can create a new tenant, configure Google + password methods, register a client.
- Test app (a tiny example) can authenticate users via that tenant.
- All admin actions appear in audit log with actor + target + diff.
- "Login as tenant user" flow (support engineer) is a separate, gated, audit-logged action — not part of normal login.

**Risks:**

- Console framework choice affects long-term maintenance. Mitigation: Phase 7 starts with a decision doc; pick based on team familiarity.
- Admin API security. Mitigation: separate scopes, separate audit trail, integration tests for authz.

**Estimated effort:** 3-4 weeks for MVP.

---

### Phase 8 — Standards & Production Hardening

**Goal:** Ship modern OAuth/OIDC features and operational features for production.

**Note:** OAuth 2.1 + OIDC Core conformance is verified continuously starting in Phase 3 via the hand-built matrix (per AD7). Phase 8 extends that matrix with new feature cases (DPoP, PAR, revoke, introspect). OIDF Conformance Suite is not in scope; see _Conformance scope_.

**Deliverables (in priority order):**

1. **PKCE required by default** (already from Phase 2; this phase enforces no opt-out for public clients).
2. **Token revocation** (RFC 7009) — `/revoke` endpoint. Handler exists in Phase 2; expose via HTTP and test.
3. **Token introspection** (RFC 7662) — `/introspect` endpoint. Same.
4. **DPoP** (RFC 9449) — sender-constrained access tokens via proof-of-possession. New `DPoP` header handling, `cnf` claim in JWT, validation on resource servers.
5. **PAR — Pushed Authorization Requests** (RFC 9126) — `/par` endpoint accepts authorization request body, returns `request_uri`; `/authorize` consumes `request_uri`.
6. **mTLS client auth** (RFC 8705) — optional for confidential clients.
7. **Dynamic Client Registration** (RFC 7591) — `/register` endpoint, gated by admin scope, audit-logged.
8. **Refresh token rotation hardening** — reuse detection escalates to invalidating all tokens for the subject (current behavior already does this; verify).
9. **Rate limiting middleware** — per-tenant, per-IP. Pluggable via a `RateLimiter` port.
10. **Structured logging + OTEL stub** — `Logger` and `Tracer` ports. Default impls log to console. Production impls integrate OTEL.

**Acceptance criteria:**

- Each RFC feature has a hand-built conformance test in `packages/openauth/test/conformance/`. No OIDF Conformance Suite integration required at this stage.
- DPoP and PAR are off by default (per-client opt-in via `ClientConfig`).
- Performance benchmark re-run; verify no >10% regression vs Phase 6 baseline.
- A small public security review of the codebase by an external party (or at minimum, internal review against OAuth 2.1 security BCP).

**Risks:**

- DPoP / PAR implementation complexity. Mitigation: take features in priority order; ship what's done.
- Rate limiting depends on infra. Mitigation: port pattern lets users plug in their own; default impl is in-memory per-instance.

**Estimated effort:** 3-4 weeks.

---

## Provider Migration Matrix

| Existing file           | New location                            | Method base                          | Effort |
| ----------------------- | --------------------------------------- | ------------------------------------ | ------ |
| `provider/apple.ts`     | `methods/providers/apple.ts`            | `oidc-generic` (with form_post hook) | M      |
| `provider/arctic.ts`    | `methods/providers/arctic.ts` (or drop) | `oauth2-generic`                     | S      |
| `provider/code.ts`      | `methods/code.ts`                       | own (credential)                     | M      |
| `provider/cognito.ts`   | `methods/providers/cognito.ts`          | `oidc-generic`                       | S      |
| `provider/discord.ts`   | `methods/providers/discord.ts`          | `oauth2-generic`                     | S      |
| `provider/facebook.ts`  | `methods/providers/facebook.ts`         | `oauth2-generic`                     | S      |
| `provider/github.ts`    | `methods/providers/github.ts`           | `oauth2-generic`                     | S      |
| `provider/google.ts`    | `methods/providers/google.ts`           | `oidc-generic`                       | S      |
| `provider/jumpcloud.ts` | `methods/providers/jumpcloud.ts`        | `oidc-generic`                       | S      |
| `provider/keycloak.ts`  | `methods/providers/keycloak.ts`         | `oidc-generic`                       | S      |
| `provider/linkedin.ts`  | `methods/providers/linkedin.ts`         | `oauth2-generic`                     | S      |
| `provider/m2m.ts`       | `methods/m2m.ts`                        | own (no routes; client fn only)      | S      |
| `provider/microsoft.ts` | `methods/providers/microsoft.ts`        | `oidc-generic` (with tenant hook)    | M      |
| `provider/oauth2.ts`    | `methods/oauth2-generic.ts`             | base method                          | L      |
| `provider/oidc.ts`      | `methods/oidc-generic.ts`               | base method                          | L      |
| `provider/passkey.ts`   | `methods/passkey.ts`                    | own (webauthn)                       | L      |
| `provider/password.ts`  | `methods/password.ts`                   | own (credential)                     | L      |
| `provider/slack.ts`     | `methods/providers/slack.ts`            | `oauth2-generic`                     | S      |
| `provider/spotify.ts`   | `methods/providers/spotify.ts`          | `oauth2-generic`                     | S      |
| `provider/twitch.ts`    | `methods/providers/twitch.ts`           | `oauth2-generic`                     | S      |
| `provider/x.ts`         | `methods/providers/x.ts`                | `oauth2-generic`                     | S      |
| `provider/yahoo.ts`     | `methods/providers/yahoo.ts`            | `oidc-generic`                       | S      |

S = small (<1 day), M = medium (1-2 days), L = large (3+ days).

---

## Cross-cutting Decisions

| Concern                   | Decision                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Password hashing          | argon2id by default. Configurable to scrypt or bcrypt for migrations only.                                                                                                                                                                                                                                                                                                                                                             |
| Cookie names              | Tenant-scoped: `auth.<tenantId>.<key>`. Avoids collisions across tenants on same domain.                                                                                                                                                                                                                                                                                                                                               |
| Cookie domain             | Defaults to host; configurable per-tenant for cross-subdomain SSO.                                                                                                                                                                                                                                                                                                                                                                     |
| State HMAC key ring       | Global symmetric key ring (32 random bytes per key, HMAC-SHA-256). Rotated monthly with overlap. Canonical API: passed directly via `IdPOptions.stateKeys: StateKeyRing`. Optional `loadStateKeyRingFromKeyStore(keyStore)` helper for operators who prefer storing the ring in `KeyStore` under a reserved id. Used only to MAC the minimal state envelope (`{ tenantId, flowId, nonce, kid }`); no sensitive data passes through it. |
| Default access token TTL  | 15 minutes.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Default refresh token TTL | 30 days, sliding. Reuse window: 60 seconds.                                                                                                                                                                                                                                                                                                                                                                                            |
| Refresh token rotation    | Required. Reuse detection invalidates all tokens for subject (existing behavior).                                                                                                                                                                                                                                                                                                                                                      |
| Auth-code TTL             | **60 seconds.** Post-callback lifetime: RP exchanges code at `/token`. Per OAuth 2.1 BCP, must be very short.                                                                                                                                                                                                                                                                                                                          |
| Flow record TTL           | **10 minutes.** Pre-callback lifetime: must survive upstream login, MFA, consent, mobile app-switching, slow network. Lives in `SessionStore`, consumed atomically on callback. Replaces the legacy 24-hour encrypted authorization-state cookie.                                                                                                                                                                                      |
| Flow cookie TTL           | Matches flow record TTL (10 minutes). HttpOnly/Secure/SameSite=Lax cookie containing only `flowId`; used as CSRF defense-in-depth in the `flow-id-in-uri` recovery path.                                                                                                                                                                                                                                                               |
| Signing key rotation      | Automatic, monthly. Old keys retained in JWKS for `accessTtl` duration.                                                                                                                                                                                                                                                                                                                                                                |
| Encryption key rotation   | Automatic, quarterly. Old keys retained for `refreshTtl` duration.                                                                                                                                                                                                                                                                                                                                                                     |
| Tenant config cache TTL   | 60 seconds. Invalidation hook fires immediately on update.                                                                                                                                                                                                                                                                                                                                                                             |
| Audit log retention       | Defined by adapter. 90 days minimum for SOC 2 readiness.                                                                                                                                                                                                                                                                                                                                                                               |
| CORS                      | Per-client allowlist, configured at client level.                                                                                                                                                                                                                                                                                                                                                                                      |
| Rate limiting             | Per-tenant per-IP. Default: 60 req/min on `/authorize`, 30 req/min on `/token`.                                                                                                                                                                                                                                                                                                                                                        |

---

## Conformance Scope

Per AD7: the IdP is verified by a **hand-built conformance matrix** running on every commit from Phase 3 onward. OIDF Conformance Suite is explicitly deferred.

**Framing the decision.** The IdP plays two interop roles, and they're not symmetric:

- **Outbound (IdP as RP of upstream providers like Google/GitHub).** `oauth4webapi` is used per AD7b. The library is already conformant; we don't write conformance tests for this surface beyond integration tests against mock upstreams.
- **Inbound (IdP as OP for tenant apps).** From the tenant app's perspective, the IdP **is** their OIDC provider. Apps validate our tokens, hit our discovery doc, run their OIDC clients against our endpoints. This is the surface that must be standards-correct, and it's where the hand-built matrix runs.

**Why not OIDF Conformance Suite (yet).** OIDF is heavy infra (Java app, deployed test harness, 30-60 minute runs) and is the right tool when:

1. A specific tenant app's OIDC client trips on a spec corner we didn't anticipate (`prompt=none`, `acr_values`, claim-level signing, `id_token` nonce binding edge cases, etc.), or
2. We pursue OpenID Certified branding for enterprise sales, or
3. An external integration partner requires it pre-flight.

None apply to the management-console-plus-internal-apps scope of this rebuild. Add OIDF later when one of those triggers fires.

**Phase 3 minimum gate** — 17 cases, all must pass before Phase 3 closes. Tests live in `packages/openauth/test/conformance/`.

| #   | Case                                      | Expected                                                             |
| --- | ----------------------------------------- | -------------------------------------------------------------------- |
| 1   | `/authorize` with required params + PKCE  | 302 to method, valid state                                           |
| 2   | `/authorize` missing required params      | OAuth error (`invalid_request` / `unsupported_response_type` / etc.) |
| 3   | `/authorize` with `response_type=token`   | Rejected — OAuth 2.1 is code-only                                    |
| 4   | `/token` with valid code + verifier       | access + refresh issued                                              |
| 5   | `/token` with already-consumed code       | `invalid_grant`                                                      |
| 6   | `/token` with expired code                | `invalid_grant`                                                      |
| 7   | `/token` with reused code                 | `invalid_grant` + revoke chain triggered                             |
| 8   | PKCE: missing `code_verifier` at `/token` | `invalid_grant`                                                      |
| 9   | PKCE: wrong `code_verifier`               | `invalid_grant`                                                      |
| 10  | PKCE: correct `code_verifier`             | success                                                              |
| 11  | Refresh with valid token                  | new tokens issued, old marked revoked                                |
| 12  | Refresh reuse detection                   | `invalid_grant` + all-tokens-for-subject revoked                     |
| 13  | `/.well-known/openid-configuration`       | valid OIDC discovery doc                                             |
| 14  | `/.well-known/jwks.json`                  | active keys + recently rotated keys                                  |
| 15  | State MAC: invalid `state`                | rejected, audit `flow_replay_attempt`                                |
| 16  | State MAC: valid `state` for wrong tenant | rejected, audit `flow_tenant_mismatch`                               |
| 17  | Two-tenant isolation                      | flow/code/refresh from tenant A unusable in tenant B                 |

**Phase 8 additions** — at least 8 more cases for the new features:

- DPoP: `htu`/`htm`/`iat`/`jti` validation, replay protection, `cnf` claim binding
- PAR: `request_uri` single-use, expiry, scoping to client
- `/revoke`: success, no-op for unknown token, audit emitted
- `/introspect`: active token, expired token, revoked token, wrong client

**Threshold for adding OIDF later.** When the first external tenant onboards or a customer explicitly asks "are you OpenID Certified?", we wire up OIDF as a nightly job (estimated 1 week of infra work, deployed against staging). Not on the critical path for the rebuild.

## Open Questions

**Resolved:**

- ✅ **AD3** — Hono. Confirmed at Phase 1 kickoff. The Hono adapter is a thin layer under `src/http/`; `domain/` and `methods/` stay framework-agnostic and `types/method.ts` is enforced framework-import-free, so AD3 is reversible later at the cost of rewriting `src/http/` only.
- ✅ **AD4** — Zod.
- ✅ **AD7** — Hand-built conformance matrix; OIDF deferred. See _Conformance scope_.
- ✅ **AD12** — In-place rebuild in `packages/openauth/src/`.
- ✅ **Package name** — stays `@_mustachio/openauth`.

**Still open (answer before the relevant phase):**

1. **Console framework.** Next.js, Astro, SvelteKit, or Remix? (Pre-Phase 7.)
2. **Storage default.** D1 or Postgres for the "out of the box" experience? Take: D1 if Cloudflare is primary deployment target; Postgres if Node. (Pre-Phase 6.)
3. **Audit log backend.** Built-in defaults? Console-only? Pluggable only? (Pre-Phase 6.)
4. **Tenant onboarding flow.** Open self-serve sign-up, invite-only, or both? Affects Phase 7 design. (Pre-Phase 7.)
5. **Effect-TS.** Revisit at end of Phase 3 — if the domain is getting tangled with Result/error plumbing, Effect may be worth adopting. (Phase 3 retro.)
6. **Registered redirect URI matching semantics.** Strawman: exact-match against `ClientConfig.redirectUris`, no wildcards or path-suffix. (Pre-Phase 3 — affects the `/authorize` validator and the `FlowRecord.callbackHost`/`callbackPath` derivation.)

---

## Risks & Mitigations

| Risk                                                        | Likelihood | Impact | Mitigation                                                                                                               |
| ----------------------------------------------------------- | ---------- | ------ | ------------------------------------------------------------------------------------------------------------------------ |
| Type system gets locked in too early, refactor needed later | M          | H      | Phase 1 is explicit type-only; don't write logic until types are stable.                                                 |
| Hono coupling leaks into domain                             | L          | M      | Architecture review at Phase 2 → Phase 3 boundary. CI rule: `domain/` cannot import `hono`.                              |
| Provider migrations stall on per-provider quirks            | M          | M      | `oauth2-generic` / `oidc-generic` expose extension hooks; document common quirks (Apple form_post, MS tenant endpoints). |
| WebAuthn complexity blocks Phase 4                          | L          | H      | Use `@simplewebauthn/server`; treat WebAuthn as opaque box that we just wire into `AuthMethod`.                          |
| Console scope creep                                         | H          | M      | MVP scope locked in Phase 7 design doc; new features go to backlog.                                                      |
| Multi-platform adapter testing pain                         | M          | M      | Use Docker / wrangler local / DynamoDB Local in CI; nightly job against real backends.                                   |
| Performance regression vs old code                          | L          | M      | Benchmark suite from Phase 3 onward; flag any handler >50ms p99 in dev.                                                  |
| Security regression vs old code                             | M          | H      | Phase 8 includes external security review; OWASP ASVS checklist; OAuth 2.1 BCP compliance verified per-feature.          |

---

## Definition of Done (overall)

This rebuild is done when:

- [ ] All 22 existing providers run on the new `AuthMethod` interface with parity to current behavior.
- [ ] All legacy files under `packages/openauth/src/` (the original `issuer.ts`, `provider/*.ts`, etc.) are deleted; only the rebuilt structure remains.
- [ ] Management console can manage 1+ tenants and ship to internal users.
- [ ] CI runs full integration tests against every storage adapter on every commit.
- [x] OAuth 2.1 + OIDC Core compliance verified via the hand-built conformance matrix (Phase 3: 17/17 cases green on every commit; Phase 8 will extend with DPoP / PAR / revoke / introspect specifics).
- [ ] DPoP, PAR, revoke, introspect available and tested. _(revoke + introspect HTTP shims shipped in Phase 3 over the existing Phase 2 domain; remaining hardening lands in Phase 8.)_
- [ ] At least one external service is using the IdP for its login (the console counts).
- [ ] A deployment runbook exists for at least 2 of: Cloudflare, AWS, Node+Postgres.

---

## Sequencing & Parallelism

```
Phase 1  ──┐
           ├─ Phase 2 ──┐
                        ├─ Phase 3 ──┬─ Phase 4 ──┐
                                      │            ├─ Phase 5 ──┐
                                      └─ (Phase 7 design) ──┐    │
                                                            │    │
                                                  Phase 6 ──┴────┤
                                                                 │
                                                                 ├─ Phase 7 ──┐
                                                                              │
                                                                  Phase 8 ────┘
```

- Phase 7 _design_ can start during Phase 5 (framework choice, mockups). Phase 7 _implementation_ needs Phase 6 (real adapters) and Phase 5 (Google method for admin login if we go that route — or skip and use passkey/code only).
- Phase 6 can run partly in parallel with Phase 5 (different work, different files).
- Phase 8 is mostly final-mile but DPoP work can start once token issuance (Phase 2) is solid.

---

## First Concrete Step (kick off Phase 1)

1. Decide on the open questions tagged **(Pre-Phase 1)** above.
2. In `packages/openauth/src/`, create the new top-level directories (`types/`, `ports/`, `domain/`, `http/`, `methods/`, `adapters/`, `util/`) alongside the existing `issuer.ts` and `provider/`. No files inside them yet beyond `.gitkeep` placeholders.
3. Write `types/result.ts`, `types/error.ts`, `types/tenant.ts`, `types/method.ts` as specified.
4. Stub `index.ts` with `createIdP` signature returning `not implemented` errors.
5. Review the types together; iterate until signed off.

Phase 1 is intentionally small — the value is in nailing the abstractions before any logic depends on them. Once those types feel right, the rest of the plan executes on top of solid ground.
