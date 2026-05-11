# Integration Guide — `@_mustachio/openauth`

This guide tells you how to embed the IdP library inside a larger host
application. It's written for engineers (human or LLM) who need a
working integration in one read-through.

**Required context before you start:**

- This package is a **server-side library**, not a standalone product.
  The host application is the product; this library is the auth brain.
- See `ARCHITECTURE.md` § "Embedding pattern" for the host/library
  boundary. Below is the short version; the boundary is not negotiable
  and reintroducing host concerns into the library will be rejected.

---

## 1. The boundary in one paragraph

The **library** owns OAuth 2.1 / OIDC Core endpoints, per-partition
isolation, the auth-method registry, the port interfaces, and the
concrete adapters. The **host** owns the console UI, the data model
(Users, Apps, Workspaces, App-Tenants), authorization (RBAC — what an
authenticated subject is allowed to do), mutations through port
adapters, inheritance logic (App defaults vs App-Tenant overrides), and
onboarding UX.

**`Tenant` is opaque to the library.** It's a partition key, not a
business concept. The library never parses it. You encode whatever
hierarchy you need (e.g. `${appId}:${appTenantId}`) into the key inside
your `resolveTenant` and your `ConfigStore`.

---

## 2. Install

```bash
bun add @_mustachio/openauth hono jose
# Plus whichever storage adapter(s) you need:
bun add postgres                  # Postgres adapter
bun add @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb   # DynamoDB
bun add @aws-sdk/client-kms       # KMS-wrapped keys
# Cloudflare D1 / KV / Durable Objects require @cloudflare/workers-types
```

Storage adapters are exposed under `@_mustachio/openauth/adapters/<backend>`.
The library has Hono as a peer dependency.

---

## 3. Public API surface (everything you'll import)

```ts
// Core entry point + types
import {
  createIdP,
  type IdP,
  type IdPOptions,
  type Result,
  type AuthError,
  authError,
  ok,
  err,
} from "@_mustachio/openauth"

// Domain types you'll touch in ConfigStore / success callback
import {
  asTenantId,
  type TenantId,
  type TenantConfig,
  type TenantContext,
  type ClientConfig,                // discriminated union
  type PublicClientConfig,
  type ConfidentialClientConfig,
  type GrantType,
  type MethodConfig,
  type SubjectSchema,
  type SubjectPayload,
  type SubjectClaim,
  type SuccessMapInput,
  type StateKeyRing,
  type StateKey,
} from "@_mustachio/openauth"

// Built-in method factories
import {
  passwordMethod,
  codeMethod,
  m2mMethod,
  passkeyMethod,
  // Generic multi-tenant factories — reach for these first when each
  // tenant brings its own OAuth 2.0 / OIDC upstream:
  oauth2Factory,
  oidcFactory,
  // Underlying primitives — `buildOauth2Method` / `buildOidcMethod` return
  // a single static `AuthMethod`. Use them inside your own custom factory
  // when the upstream config is compile-time constant (single-tenant
  // deployments). The factories above wrap them for the multi-tenant case.
  buildOauth2Method,
  buildOidcMethod,
} from "@_mustachio/openauth"

// 15 pre-configured upstream provider factories
import {
  googleFactory,
  githubFactory,
  appleFactory,
  microsoftFactory,
  discordFactory,
  facebookFactory,
  linkedinFactory,
  slackFactory,
  spotifyFactory,
  twitchFactory,
  xFactory,
  yahooFactory,
  jumpcloudFactory,
  keycloakFactory,
  cognitoFactory,
} from "@_mustachio/openauth"

// Port interfaces (implement these only if you don't use bundled adapters)
import type {
  ConfigStore,
  TokenStore,
  SessionStore,
  KeyStore,
  MethodStore,
  AuditLog,
  AuditEvent,
} from "@_mustachio/openauth"
```

---

## 4. Storage adapters — pick by deployment target

| Deployment | Recommended stack |
|---|---|
| **Node + Postgres** | All ports from `@_mustachio/openauth/adapters/postgres` |
| **Cloudflare Workers** | `ConfigStore` + `MethodStore` + `AuditLog` from `/adapters/kv`; `TokenStore` from `/adapters/d1`; `SessionStore` from `/adapters/durable-object`; `KeyStore` from `/adapters/d1` |
| **AWS Lambda** | All ports from `/adapters/dynamo`; optionally `KeyStore` from `/adapters/kms` for HSM-grade key wrapping |
| **Dev / Tests** | All ports from `/adapters/memory` |

**Hard constraint:** `TokenStore` and `SessionStore` require strong CAS.
Cloudflare KV is **not** acceptable for those two ports. See
`ports/CONSISTENCY.md`.

---

## 5. The four host-side contracts

The library calls into the host through four user-supplied surfaces.
Implement them and you're done.

### 5.1 `resolveTenant(req): Promise<Result<TenantId>>`

Maps an incoming `Request` to your partition key. This runs only for
the **first** request in a flow — callbacks recover the tenant from the
MAC-bound state envelope.

**Canonical pattern when you have two scoping levels (`App` ⇒
`App-Tenant`):** encode the tuple into the key.

```ts
async function resolveTenant(req: Request): Promise<Result<TenantId, AuthError>> {
  const url = new URL(req.url)
  const clientId = url.searchParams.get("client_id")
  if (!clientId) {
    return err(authError.invalidRequest("missing client_id"))
  }

  // Your DB lookups:
  const app = await db.apps.findByOAuthClientId(clientId)
  if (!app) {
    return err(authError.tenantNotFound("unknown client", ""))
  }

  // Optional: derive sub-partition from subdomain / header / etc.
  const subdomain = url.hostname.split(".")[0]
  const appTenant = await db.appTenants.findBySubdomain(app.id, subdomain)

  return ok(asTenantId(`${app.id}:${appTenant?.id ?? "__default__"}`))
}
```

### 5.2 `ConfigStore` — return the resolved `TenantConfig`

This is where you merge App defaults with App-Tenant overrides. The
framework gets one final `TenantConfig`; it doesn't know about your
inheritance model.

```ts
import type { ConfigStore } from "@_mustachio/openauth"

const configStore: ConfigStore = {
  async getTenantConfig(id) {
    const [appId, subId] = (id as string).split(":")
    const app = await db.apps.get(appId)
    if (!app) {
      return err(authError.tenantNotFound("unknown app", id))
    }
    const appTenant =
      subId === "__default__" ? null : await db.appTenants.get(subId)

    return ok({
      id,
      displayName: appTenant?.displayName ?? app.name,
      clients: [
        {
          id: app.oauthClientId,
          name: app.name,
          type: "confidential",             // or "public" for SPA / mobile
          secretHash: app.oauthClientSecretHash, // sha256+base64url (see §10)
          redirectUris: app.allowedRedirectUris,
          grantTypes: ["authorization_code", "refresh_token"],
          scopes: app.allowedScopes,
          pkceRequired: true,
        },
      ],
      // App defaults overridden by App-Tenant settings:
      methods: appTenant?.providers ?? app.defaultProviders,
      theme: app.theme,
      cookieDomain: app.cookieDomain ?? undefined,
    })
  },

  // Optional — called by the framework when it wants to register a
  // cache-invalidation hook. Return a function that, when called,
  // tells the framework "this tenant's config changed."
  onTenantConfigChanged: undefined, // omit if you don't have invalidation
}
```

**`ClientConfig` is a discriminated union.** Type your literal carefully:

```ts
// Public client (SPA, mobile, native):
{
  id: "spa-client",
  name: "Web app",
  type: "public",
  redirectUris: [...],
  grantTypes: ["authorization_code", "refresh_token"],
  scopes: [...],
  pkceRequired: true,    // MUST be the literal `true` — public + false is a compile error
}

// Confidential client (server, M2M):
{
  id: "api-client",
  name: "API server",
  type: "confidential",
  secretHash: "<sha256(secret) as base64url>",  // REQUIRED
  redirectUris: [...],
  grantTypes: ["authorization_code", "refresh_token", "client_credentials"],
  scopes: [...],
  pkceRequired: true,    // recommended, may be false
}
```

### 5.3 `success(input): Promise<SubjectClaim>`

Required. Maps an auth-method result into the typed subject your IdP
will issue. Runs at `/token` time after PKCE verification, before
tokens are minted.

```ts
const success = async (input: SuccessMapInput): Promise<SubjectClaim> => {
  const { tenant, methodId, methodKind, providerSubject, properties } = input

  // Look up or create your internal user. The library doesn't know what
  // a "user" is — you decide.
  const user = await db.users.upsertByProviderIdentity({
    tenantId: tenant.id,
    methodKind,                  // "google" | "password" | "passkey" | ...
    providerSubject,             // Google's `sub`, password row's user_id, etc.
    properties,                  // typed per method
  })

  // Decide what subject type to issue. You can issue different types
  // for different cohorts ("admin" vs "user", etc).
  return {
    type: "user",
    properties: {
      userId: user.id,
      email: user.email,
    },
  }
}
```

### 5.4 `subjects: SubjectSchema` — declare your subject types

A `Record<string, StandardSchema>` (Zod recommended) that defines the
shape of each subject type the IdP can issue.

```ts
import { z } from "zod"

const subjects = {
  user: z.object({
    userId: z.string(),
    email: z.string().email(),
  }),
  admin: z.object({
    adminId: z.string(),
    roles: z.array(z.string()),
  }),
} satisfies SubjectSchema
```

---

## 6. State-MAC key ring

The library MACs the OAuth `state` envelope with a global symmetric
key. Generate 32 random bytes, persist them somewhere durable, and
rotate monthly.

```ts
import { randomBytes } from "node:crypto"

const stateKeys: StateKeyRing = {
  active: {
    kid: "2026-05",
    key: new Uint8Array(/* load 32 bytes from env / secrets manager */),
  },
  verify: [
    // Include `active` plus any previous keys still in their overlap window.
    { kid: "2026-05", key: /* same as active */ },
    { kid: "2026-04", key: /* previous month's key */ },
  ],
}
```

Operators preferring to store the ring inside `KeyStore` can use the
helper exported from `@_mustachio/openauth/util` (see plan
§"Cross-cutting Decisions").

---

## 7. Minimum viable integration (Node + Postgres)

```ts
import postgres from "postgres"
import {
  createIdP,
  asTenantId,
  authError,
  ok,
  err,
  passwordMethod,
  googleFactory,
  type SubjectSchema,
} from "@_mustachio/openauth"
import {
  fromPostgresJs,
  migrate,
  PostgresAuditLog,
  PostgresConfigStore,
  PostgresKeyStore,
  PostgresMethodStore,
  PostgresSessionStore,
  PostgresTokenStore,
} from "@_mustachio/openauth/adapters/postgres"
import { z } from "zod"

// 1. Storage setup
const sql = postgres(process.env.DATABASE_URL!)
const exec = fromPostgresJs(sql)
await migrate(exec)   // idempotent; creates tables on first run

const keyStore = new PostgresKeyStore({ exec })
const tokenStore = new PostgresTokenStore({ exec, keyStore })
const sessionStore = new PostgresSessionStore({ exec })
const auditLog = new PostgresAuditLog({ exec })
// ConfigStore + MethodStore — wire to your own DB instead if you prefer
const configStore = new PostgresConfigStore({ exec })
const methodStore = new PostgresMethodStore({ exec })

// 2. Method factories
const methods = {
  password: passwordMethod({
    users: {
      async findByEmail({ tenantId, email }) {
        return db.users.find(tenantId, email)
      },
    },
  }),
  google: googleFactory,
}

// 3. Subject schema
const subjects = {
  user: z.object({
    userId: z.string(),
    email: z.string().email(),
  }),
} satisfies SubjectSchema

// 4. Compose
const idp = createIdP({
  resolveTenant: async (req) => {
    const url = new URL(req.url)
    const clientId = url.searchParams.get("client_id")
    if (!clientId) return err(authError.invalidRequest("missing client_id"))
    return ok(asTenantId(clientId))
  },
  stateKeys: loadStateKeyRing(),
  configStore,
  tokenStore,
  sessionStore,
  keyStore,
  methodStore,
  auditLog,
  issuerUrl: "https://auth.yourapp.com",
  methods,
  subjects,
  success: async ({ methodKind, providerSubject, properties }) => ({
    type: "user",
    properties: {
      userId: await db.users.upsert({ methodKind, providerSubject }),
      email: (properties as { email?: string }).email ?? "",
    },
  }),
})

// 5. Serve
Bun.serve({
  port: 3000,
  fetch: idp.handle,    // export default { fetch: idp.handle } for Workers
})
```

That's a complete IdP. It serves `/authorize`, `/token`, `/cb/*`,
`/userinfo`, `/revoke`, `/introspect`, `/.well-known/*` over Postgres
with password + Google sign-in.

---

## 8. Mounting alongside an existing app

The library returns an `IdP` handle with per-endpoint accessors:

```ts
type IdP = {
  handle: (req: Request) => Promise<Response>   // single fetch entrypoint
  authorize: (req: Request) => Promise<Response>
  token: (req: Request) => Promise<Response>
  userinfo: (req: Request) => Promise<Response>
  jwks: (req: Request) => Promise<Response>
  discovery: (req: Request) => Promise<Response>
  revoke?: (req: Request) => Promise<Response>
  introspect?: (req: Request) => Promise<Response>
}
```

Use `idp.handle` for full delegation. For mounting under a prefix or
alongside your admin routes:

```ts
import { Hono } from "hono"
const app = new Hono()

app.get("/health", (c) => c.text("ok"))
app.route("/auth", honoWrap(idp.handle))   // see below
app.get("/console/*", consoleHandler)       // your own UI
```

Where `honoWrap` strips the `/auth` prefix before delegating:

```ts
function honoWrap(fn: (req: Request) => Promise<Response>) {
  return new Hono().all("/*", async (c) => {
    const url = new URL(c.req.url)
    url.pathname = url.pathname.replace(/^\/auth/, "") || "/"
    return fn(new Request(url, c.req.raw))
  })
}
```

**Path-based tenant routing** — if you have URLs like
`/tenant/:tenantId/authorize`, do the mapping in `resolveTenant`:

```ts
async function resolveTenant(req: Request): Promise<Result<TenantId, AuthError>> {
  const m = /^\/tenant\/([^/]+)\//.exec(new URL(req.url).pathname)
  if (!m) return err(authError.invalidRequest("missing tenant path"))
  return ok(asTenantId(m[1]!))
}
```

---

## 9. Method configuration

### 9.1 Built-in method factories

The factory shape splits **behavioral hooks** (host-supplied functions —
how to deliver a code, where credentials live) from **per-tenant data**
(form titles, RP IDs, code length, etc.). Hooks live on the factory
creation call; tenant data lives on `MethodConfig.config` and is
validated against the factory's Zod `configSchema` at request time.

```ts
// Password — argon2id; opt-in registration. Hook: where users live.
passwordMethod({
  users: {
    async findByEmail({ tenantId, email }) { /* ... */ },
    async create?({ tenantId, email, passwordHash }) { /* ... */ },
  },
  enableRegistration: false,
  title: "Sign in",
})

// Email/SMS code — magic link by another name.
// Factory: only `sendCode` (and optional `generateCode`).
// Per-tenant config: codeLength?, maxAttempts?, destinationKind?, titles?
codeMethod({
  async sendCode({ destination, code, tenantId }) {
    await sendgrid.send({ to: destination, code })
  },
})

// M2M (client_credentials grant).
m2mMethod({
  async resolveSubject({ tenantId, clientId, scope, params }) {
    return { providerSubject: clientId, properties: { tier: "premium" } }
  },
})

// WebAuthn passkey — multi-tenant.
// Factory: only `credentials` (the credential store).
// Per-tenant config: { rpName, rpID, origins, title? }.
// `rpID` and `origins` are usually per-tenant because each customer
// runs on their own domain.
passkeyMethod({
  credentials: {
    async findByUsername(username, tenantId) { /* ... */ },
    async findById(credentialId, tenantId) { /* ... */ },
    async updateCounter({ credentialId, counter, tenantId }) { /* ... */ },
    async create?({ userId, credential, tenantId }) { /* ... */ },
  },
})
```

The corresponding `MethodConfig.config` shapes (what hosts put inside
their `TenantConfig.methods[]` entries):

```ts
// codeMethod — all fields optional; defaults documented in the schema.
{ id: "code", kind: "code", type: "code", enabled: true, config: {
  codeLength: 6,                   // 4-10, default 6
  maxAttempts: 5,                  // default 5
  destinationKind: "email",        // "email" | "tel" | "any"
  titles: { request: "Sign in", verify: "Enter your code" },
}}

// passkeyMethod — rpName / rpID / origins required.
{ id: "passkey", kind: "passkey", type: "passkey", enabled: true, config: {
  rpName: "Acme",
  rpID: "acme.example",
  origins: "https://acme.example",          // or ["https://...", ...]
  title: "Sign in with passkey",
}}
```

### 9.2 OAuth/OIDC providers — multi-instance per tenant

A tenant can register multiple instances of the same factory by giving
each a unique `id` (URL path) while sharing a `kind` (factory lookup):

```ts
// Two Google instances — Workspace SSO + consumer sign-in:
const methods = {
  google: googleFactory,    // map key MUST equal factory.kind
}

// In TenantConfig.methods:
[
  {
    id: "google-workspace",     // becomes /google-workspace/* in URLs
    kind: "google",
    type: "oidc",
    enabled: true,
    config: {
      clientId: "...workspace...",
      clientSecret: "...",
      hostedDomain: "yourcompany.com",
    },
  },
  {
    id: "google-personal",
    kind: "google",
    type: "oidc",
    enabled: true,
    config: { clientId: "...personal...", clientSecret: "..." },
  },
]
```

In your `success` callback, `methodId` tells you which instance was
used; `methodKind` tells you which provider:

```ts
success: async ({ methodId, methodKind, providerSubject }) => {
  // methodKind === "google" for both instances.
  // methodId === "google-workspace" or "google-personal".
  if (methodId === "google-workspace") {
    return { type: "admin", properties: { /* ... */ } }
  }
  return { type: "user", properties: { /* ... */ } }
}
```

### 9.3 Generic OAuth 2.0 / OIDC factories (multi-tenant)

For providers not in the built-in 15 — or for the common case where
each tenant brings its own issuer / client credentials — use
`oauth2Factory` or `oidcFactory`. They're factories (multi-instance,
per-tenant config) rather than single static methods.

```ts
import { oauth2Factory, oidcFactory } from "@_mustachio/openauth"

const methods = {
  oauth2: oauth2Factory,
  oidc: oidcFactory,
}

// Per-tenant MethodConfig:
{
  id: "internal-sso",            // becomes /internal-sso/* in URLs
  kind: "oauth2",                 // matches the factory key
  type: "oauth2",
  enabled: true,
  config: {                       // validated against oauth2Factory.configSchema
    clientId: "...",
    clientSecret: "...",
    scopes: ["read"],
    authorizationUrl: "https://internal.example/oauth/authorize",
    tokenUrl: "https://internal.example/oauth/token",
  },
}

{
  id: "okta",
  kind: "oidc",
  type: "oidc",
  enabled: true,
  config: {                       // validated against oidcFactory.configSchema
    issuer: "https://yourtenant.okta.com",
    clientId: "...",
    clientSecret: "...",
    // scopes optional — defaults to ["openid", "email", "profile"]
    // endpoints optional — supply if discovery is unavailable
  },
}
```

Each tenant can register many instances of the same factory by using
distinct `id` values — e.g. `okta-internal` and `okta-customers` both
backed by `kind: "oidc"`.

### 9.4 Single static AuthMethod (single-tenant only)

`buildOauth2Method` and `buildOidcMethod` are the underlying primitives.
They return a single `AuthMethod` instance — not a factory — so you call
them inside your own `AuthMethodFactory.build` when the upstream config
is a compile-time constant (single-tenant deployments, or for writing a
vendor-specific factory like the ones in `methods/providers/`).

```ts
import type { AuthMethodFactory } from "@_mustachio/openauth"
import { z } from "zod"

const myOkta: AuthMethodFactory<Oauth2Properties, Oauth2State, {}> = {
  kind: "my-okta",
  configSchema: z.object({}),
  build: async ({ id, kind }) =>
    buildOidcMethod({
      id,
      kind,
      issuer: process.env.OKTA_ISSUER!,
      clientId: process.env.OKTA_CLIENT_ID!,
      clientSecret: process.env.OKTA_CLIENT_SECRET!,
      scopes: ["openid", "email", "profile"],
    }),
}
```

Reach for `oauth2Factory` / `oidcFactory` first; only drop down to the
builders when the upstream is fixed at the deployment level.

---

## 10. Subject identity & JWT validation in your services

Access tokens are JWTs (ES256). Your downstream services validate them
against `/.well-known/jwks.json`:

```ts
import { jwtVerify, createRemoteJWKSet } from "jose"

const JWKS = createRemoteJWKSet(new URL("https://auth.yourapp.com/.well-known/jwks.json"))

async function authMiddleware(req: Request) {
  const bearer = req.headers.get("authorization")?.replace(/^Bearer /, "")
  if (!bearer) throw new Error("no bearer")
  const { payload } = await jwtVerify(bearer, JWKS, {
    issuer: "https://auth.yourapp.com",
  })
  // payload.tid     -- TenantId partition the subject belongs to
  // payload.sub     -- stable subject id derived from the SubjectClaim
  // payload.aud     -- client_id (the audience)
  // payload.scope   -- space-separated granted scopes
  // payload.mid     -- methodId that produced the subject
  // payload.mkind   -- methodKind (e.g. "google", "password")
  // payload.claim   -- the SubjectClaim ({ type, properties }) verbatim
  return payload
}
```

**Authorization is your job.** The library tells you who the subject
is; deciding whether they can do something is the host's middleware.

---

## 11. Audit log access

The library writes audit events through your `AuditLog` adapter. Read
access is **a host concern** — query your underlying store directly:

```ts
// Postgres example (the bundled adapter writes to `openauth_audit_log`):
const events = await sql`
  SELECT * FROM openauth_audit_log
  WHERE tenant_id = ${tenantId}
    AND kind IN ('token_issued', 'token_revoked')
    AND timestamp > ${cutoff}
  ORDER BY timestamp DESC
  LIMIT 100
`
```

Audit event kinds the library emits:

```
authorize_started, authorize_completed, authorize_rejected,
flow_replay_attempt, flow_tenant_mismatch, flow_callback_mismatch,
unrecoverable_flow,
token_issued, token_refreshed, token_revoked, refresh_reuse_detected
```

---

## 12. Client-secret hashing

When you store `secretHash` in `ConfigStore`, hash the plaintext with
SHA-256 + base64url:

```ts
// Match exactly what the library does at verification time:
function hashClientSecret(plain: string): string {
  const bytes = new TextEncoder().encode(plain)
  return Buffer.from(crypto.createHash("sha256").update(bytes).digest())
    .toString("base64url")
}
```

(This format is documented in `domain/token.ts:hashClientSecret`.
Production deployments will migrate to argon2id in a future Phase 8
session; the storage shape — a `string` — won't change.)

---

## 13. Behavioral contracts to know

- **PKCE is enforced for every public client.** `pkceRequired: true` is
  the only legal value on `PublicClientConfig`. Confidential clients can
  set `pkceRequired: false` but it's not recommended.
- **Refresh-token grant authenticates the client.** Confidential clients
  MUST present `client_secret` (Basic auth or form body) when
  refreshing. Anonymous refresh = `401 invalid_client`.
- **`/introspect` requires client auth** (RFC 7662 §2.1) and only
  returns claims to the client named in `aud`. Cross-client introspect
  returns `{active: false}` to avoid token-existence leaks.
- **`/revoke` authenticates confidential-client tokens** (RFC 7009 §2.1).
  Public-client tokens can be revoked anonymously. Wrong-client revoke
  = `400 invalid_grant` without consuming.
- **Auth-code TTL is fixed at 60 s** by OAuth 2.1 BCP. The library
  refuses larger TTLs at the storage layer.
- **Refresh-token reuse triggers family revocation.** Detected reuse
  within the 60 s window invalidates every token in the family and
  audits `refresh_reuse_detected`.
- **One callback consume per flow.** The framework's recovery chain
  consumes the `FlowRecord` exactly once before dispatching the method
  callback. Methods observe via `MethodContext`; they do not call
  `SessionStore` directly to mutate.
- **`Cookie` headers from method responses are stripped** by the HTTP
  adapter and replaced with the framework's own cookie serializer.
  Methods set cookies via `MethodResult.setCookies`, never via
  `Response.headers.set("set-cookie", ...)`.

---

## 14. Things you must NOT do

These are antipatterns that will break the embedding contract or
introduce security bugs:

- **Don't add an admin HTTP surface to the library.** The host imports
  port adapters in-process; there is no boundary to protect with
  `/admin/*` routes.
- **Don't try to parse `TenantId`.** It's opaque. The framework never
  splits it; neither should anything that reads it back from a JWT.
- **Don't store the state-MAC key inside `TenantConfig`.** The MAC has
  to verify *before* the tenant is loaded; per-tenant keys create a
  bootstrap problem.
- **Don't issue tokens outside `createIdP`.** If you need an
  impersonation token for support tools, sign one manually with
  `KeyStore.currentSigningKey()` + `jose` — but treat it as a host
  operation, not a library operation.
- **Don't share `SubjectClaim` shapes across tenants without checking
  `tid`.** Two tenants may issue `type: "user"` with the same
  `properties.userId` and they are different subjects. Always
  partition-scope your lookups.

---

## 15. Phase 8 features that are NOT yet in the library

If you need any of these and want them on the library side rather than
in front of it, raise scope before integrating:

- **DPoP (RFC 9449)** — sender-constrained tokens. Bearer tokens only
  for now.
- **PAR (RFC 9126)** — pushed authorization requests.
- **mTLS client auth (RFC 8705)** — relies on a host-side
  `extractClientCert(req)` hook that doesn't exist yet.
- **Dynamic Client Registration (RFC 7591)** — host-callable helper
  pattern, not landed yet.
- **Rate-limiter port** — put rate limits in your proxy / CDN / WAF in
  front of the IdP for now.
- **Logger / Tracer ports** — wrap `idp.handle` with your own
  request-logging middleware until structured ports land.

All of these are designed to be **additive when they ship**: new
optional fields on `IdPOptions`, new optional methods on existing
ports. Integrating today does not require an overhaul to pick them up
later.

---

## 16. Verifying your integration

Steel-thread these in order — each one exercises a different piece of
the wiring:

1. **`GET /.well-known/openid-configuration`** returns a valid OIDC
   discovery doc. Smoke test that the issuer URL, endpoints, and
   `code_challenge_methods_supported: ["S256"]` all show up.
2. **`GET /authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256`**
   returns 302 with a `state` query param on the redirect.
3. **Walk a full auth flow** with a stub method (or the password
   method) and confirm `/token` issues `access_token` + `refresh_token`.
4. **Validate the JWT** against your JWKS endpoint from a downstream
   service. Confirm `iss`, `aud`, `tid`, `sub` are all what you expect.
5. **Refresh once.** Confirm the new refresh token differs from the old
   and that the old returns `invalid_grant` on second use.
6. **Revoke the refresh token.** Confirm subsequent refresh attempts
   fail and that `auditLog.byKind("token_revoked")` records the event.
7. **Two-tenant isolation.** Issue a token in tenant A and confirm it
   doesn't validate as tenant B's audience.

Each of these has a corresponding case in
`test/conformance/oauth-2.1.test.ts` you can crib from.

---

## 17. Where to look in the codebase

| You want to understand | Read |
|---|---|
| The embedding contract | `ARCHITECTURE.md` § "Embedding pattern" |
| Port consistency requirements | `src/ports/CONSISTENCY.md` |
| The phased build history + decisions | `docs/plans/claude/idp-rebuild-plan.md` |
| Public type shapes | `src/types/*.ts` |
| What's expected of each port impl | `test/ports/*.ts` (parameterized conformance suite) |
| Example end-to-end flow under memory adapters | `test/integration/full-flow.test.ts` |
| Conformance behavior the library guarantees | `test/conformance/oauth-2.1.test.ts` |
