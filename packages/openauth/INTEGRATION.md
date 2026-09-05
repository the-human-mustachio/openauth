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
  type ClientConfig, // discriminated union
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
  // OIDC token-response types — accept these from the library when you
  // proxy /token responses through host-side middleware.
  type IdTokenClaims,
  type ScopedProfileClaims,
  type AddressClaim,
  // Dynamic Client Registration (RFC 7591) — implement the hook if you
  // want to expose `POST /register` on your IdP.
  type RegisterClient,
  type RegisterClientRequest,
  type RegisterClientResponse,
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

| Deployment             | Recommended stack                                                                                                                                                                |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Node + Postgres**    | All ports from `@_mustachio/openauth/adapters/postgres`                                                                                                                          |
| **Cloudflare Workers** | `ConfigStore` + `MethodStore` + `AuditLog` from `/adapters/kv`; `TokenStore` from `/adapters/d1`; `SessionStore` from `/adapters/durable-object`; `KeyStore` from `/adapters/d1` |
| **AWS Lambda**         | All ports from `/adapters/dynamo`; optionally `KeyStore` from `/adapters/kms` for HSM-grade key wrapping                                                                         |
| **Dev / Tests**        | All ports from `/adapters/memory`                                                                                                                                                |

Per-port adapter coverage (every cell is a bundled, conformance-tested
adapter; "—" means not implemented and the alternatives in the same
row cover that backend):

| Port                     | memory | postgres | d1  | dynamo | kv           | durable-object | kms |
| ------------------------ | ------ | -------- | --- | ------ | ------------ | -------------- | --- |
| `TokenStore`             | ✓      | ✓        | ✓   | ✓      | — (eventual) | —              | —   |
| `SessionStore`           | ✓      | ✓        | ✓   | ✓      | — (eventual) | ✓              | —   |
| `KeyStore`               | ✓      | ✓        | ✓   | ✓      | —            | —              | ✓   |
| `ConfigStore`            | ✓      | ✓        | ✓   | ✓      | ✓            | —              | —   |
| `MethodStore`            | ✓      | ✓        | ✓   | ✓      | ✓            | —              | —   |
| `AuditLog`               | ✓      | ✓        | ✓   | ✓      | ✓            | —              | —   |
| `PasskeyCredentialStore` | ✓      | ✓        | —   | ✓      | —            | —              | —   |

**Hard constraint:** `TokenStore` and `SessionStore` require strong CAS.
Cloudflare KV is **not** acceptable for those two ports. See
`ports/CONSISTENCY.md`. `PasskeyCredentialStore` similarly needs
strong reads for the signature-counter update path, which rules out KV.

### 4a. `KeyStore` at-rest encryption — required in production

`PostgresKeyStore` and `DynamoKeyStore` persist JWT signing-key private
material and the symmetric encryption-key bytes used for at-rest payload
encryption (auth codes, future refresh-payload encryption). By default
both adapters write that material **in plaintext** to the underlying
column / attribute — convenient for dev, **not acceptable for production**
deployments where a read-only DB compromise (SQL injection elsewhere,
leaked backup, replica access, snapshot exfil) would yield full
token-forging power for every tenant.

Pass a `KeyWrapper` to either adapter to enable envelope encryption:

```ts
import { PostgresKeyStore, type KeyWrapper } from "@_mustachio/openauth"
import { KMSClient, EncryptCommand, DecryptCommand } from "@aws-sdk/client-kms"

const kms = new KMSClient({})
const KeyId = process.env.OPENAUTH_KMS_KEY_ARN!

const wrapper: KeyWrapper = {
  async wrap(plaintext) {
    const r = await kms.send(
      new EncryptCommand({ KeyId, Plaintext: plaintext }),
    )
    return new Uint8Array(r.CiphertextBlob!)
  },
  async unwrap(ciphertext) {
    const r = await kms.send(new DecryptCommand({ CiphertextBlob: ciphertext }))
    return new Uint8Array(r.Plaintext!)
  },
}

const keyStore = new PostgresKeyStore({ exec, wrapper })
```

Other valid backings: GCP KMS `Encrypt`/`Decrypt`, Vault transit
`encrypt`/`decrypt`, HSM-backed code. `@_mustachio/openauth/adapters/kms`
ships a higher-level `KmsKeyStore` that bakes the same envelope pattern
in directly and is usually the simpler choice on AWS — reach for
`PostgresKeyStore`/`DynamoKeyStore` + `wrapper` only when your KMS isn't
AWS or you want one storage backend for all ports.

Without a wrapper, the adapter records `private_jwk_wrapped = false`
(Postgres) or `private_jwk_wrapped: false` (Dynamo); flipping a wrapper
on later is forward-compatible (legacy rows continue to read as
plaintext), but operators rotating into wrapped storage should re-key by
provisioning fresh signing/encryption keys after wiring the wrapper.

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
async function resolveTenant(
  req: Request,
): Promise<Result<TenantId, AuthError>> {
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

**`client_credentials` grant note.** A `POST /token` for `grant_type=client_credentials` carries `client_id` in the form body / Basic-auth header, not the URL. The framework parses the body and _injects_ the resolved `client_id` into the request's URL search params before calling `resolveTenant`, so the canonical pattern above works identically for m2m — no separate hook is needed. (If the request already has a `client_id` query param, the framework leaves it alone.)

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
          type: "confidential", // or "public" for SPA / mobile
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
    methodKind, // "google" | "password" | "passkey" | ...
    providerSubject, // Google's `sub`, password row's user_id, etc.
    properties, // typed per method
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

### 5.5 `buildCustomContext(req)` — per-request blob for methods & `success`

Optional. Build whatever per-request data the host wants downstream
code to see (request id, decoded edge JWT claims, mTLS cert info, geo
hints). The returned record becomes:

- `TenantContext.request.custom` for the same-request entrypoints
  (`/authorize`, `/token`, `/userinfo`, `/revoke`, `/introspect`).
- `FlowRecord.context` on the saved flow (so it survives the upstream
  redirect chain).
- `SuccessMapInput.context` when the `success` callback runs at
  `/token` time.

```ts
const idp = createIdP({
  resolveTenant,
  configStore,
  // …
  buildCustomContext(req) {
    return {
      requestId: req.headers.get("x-request-id") ?? randomUUID(),
      edgeIp: req.headers.get("x-forwarded-for") ?? null,
    }
  },
})
```

The hook may return a plain object or a `Promise<Record<string,
unknown>>`. Without it the blob is `{}` and `SuccessMapInput.context`
is `null` — there's no semantic difference between an absent hook and
one that returns `{}`.

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
await migrate(exec) // idempotent; creates tables on first run

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
  fetch: idp.handle, // export default { fetch: idp.handle } for Workers
})
```

That's a complete IdP. It serves `/authorize`, `/token`, `/cb/*`,
`/userinfo`, `/revoke`, `/introspect`, `/end_session`, `/par`,
`/register`, `/.well-known/*` over Postgres with password + Google
sign-in.

---

## 8. Mounting alongside an existing app

The library returns an `IdP` handle with per-endpoint accessors:

```ts
type IdP = {
  handle: (req: Request) => Promise<Response> // single fetch entrypoint
  authorize: (req: Request) => Promise<Response>
  token: (req: Request) => Promise<Response>
  userinfo: (req: Request) => Promise<Response>
  jwks: (req: Request) => Promise<Response>
  discovery: (req: Request) => Promise<Response>
  revoke: (req: Request) => Promise<Response>
  introspect: (req: Request) => Promise<Response>
  endSession: (req: Request) => Promise<Response> // OIDC RP-Initiated Logout 1.0
  par: (req: Request) => Promise<Response> // RFC 9126 Pushed Authorization Requests
  register: (req: Request) => Promise<Response> // RFC 7591 Dynamic Client Registration
}
```

Use `idp.handle` for full delegation. For mounting under a prefix or
alongside your admin routes:

```ts
import { Hono } from "hono"
const app = new Hono()

app.get("/health", (c) => c.text("ok"))
app.route("/auth", honoWrap(idp.handle)) // see below
app.get("/console/*", consoleHandler) // your own UI
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
async function resolveTenant(
  req: Request,
): Promise<Result<TenantId, AuthError>> {
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
    async findByEmail({ tenantId, email }) {
      /* ... */
    },
    async create?({ tenantId, email, passwordHash }) {
      /* ... */
    },
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
//
// The bundled adapters under @_mustachio/openauth/adapters/{memory,
// postgres,dynamo} ship a ready-to-use credential store. For Postgres,
// the schema is created by the same `migrate()` call you run for the
// other tables:
import { PostgresPasskeyCredentialStore } from "@_mustachio/openauth/adapters/postgres"

passkeyMethod({
  credentials: new PostgresPasskeyCredentialStore({ exec }),
})

// Or for AWS Lambda / DynamoDB:
//   import { DynamoPasskeyCredentialStore } from "@_mustachio/openauth/adapters/dynamo"
//   passkeyMethod({ credentials: new DynamoPasskeyCredentialStore({ exec }) })
//
// Or write your own against existing user-management tables — the
// interface is four small methods, all framework-internal:
//   findByUsername(username, tenantId) → { userId, credentials[] } | null
//   findById(credentialId, tenantId)   → StoredCredential | null
//   updateCounter({ credentialId, counter, tenantId })
//   create?({ userId, credential, tenantId })  -- omit to disable registration
```

**Reference-adapter simplification.** All three bundled stores
(memory / postgres / dynamo) treat `userId` as the username lookup
key. This matches the bundled `passkeyMethod`, which sets
`userId = parsed.data.username` at registration. Hosts that need
`username ≠ userId` (e.g. usernames may rebrand without re-issuing
credentials) write their own `PasskeyCredentialStore` against their
own user model — see `src/adapters/postgres/passkey-credential-store.ts`
as a one-page reference for the SQL shape, then swap the `WHERE
user_id = $2` clause for a join against your `users` table by
username.

**Writing a custom adapter — quick sketch.** The interface is plain
async functions, no `Result<T>` wrapping:

```ts
import type { PasskeyCredentialStore } from "@_mustachio/openauth"

class MyPasskeyStore implements PasskeyCredentialStore {
  constructor(private db: MyDb) {}

  async findByUsername(username, tenantId) {
    const user = await this.db.users.byUsername({ username, tenantId })
    if (!user) return null
    const rows = await this.db.passkeys.byUserId({ userId: user.id, tenantId })
    return { userId: user.id, credentials: rows.map(toStoredCredential) }
  }

  async findById(credentialId, tenantId) {
    const row = await this.db.passkeys.byCredentialId({
      credentialId,
      tenantId,
    })
    return row ? toStoredCredential(row) : null
  }

  async updateCounter({ credentialId, counter, tenantId }) {
    await this.db.passkeys.updateCounter({ credentialId, counter, tenantId })
  }

  async create({ userId, credential, tenantId }) {
    await this.db.passkeys.insert({
      tenantId,
      userId,
      credentialId: credential.credentialId,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports ?? null,
    })
  }
}
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
    return {
      type: "admin",
      properties: {
        /* ... */
      },
    }
  }
  return {
    type: "user",
    properties: {
      /* ... */
    },
  }
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

### 9.5 SAML SP — enterprise SAML 2.0 connections

`samlSpFactory` adds SAML 2.0 **Service Provider** support: the library
consumes signed assertions from a corporate IdP (Okta, Entra, Ping,
ADFS, …). It never issues assertions — downstream apps still speak your
OIDC issuer. It is just another `AuthMethodFactory`; the `/authorize`
dispatch, state envelope, flow record, and `success` callback all work
unchanged.

**Node-only — separate subpath.** Everything SAML lives at the
`@_mustachio/openauth/methods/saml-sp` subpath, which carries a `node`
export condition. The root entry (`@_mustachio/openauth`) never
re-exports it, so Workers / browser builds stay edge-clean by
construction. SAML deployments must run on Node — Workers / Durable
Object / D1 deployments continue to use OAuth/OIDC methods.

```ts
// Node host only:
import {
  samlSpFactory,
  type SamlSpConfig,
} from "@_mustachio/openauth/methods/saml-sp"

const methods = {
  "saml-sp": samlSpFactory, // map key MUST equal factory.kind
}
```

**SessionStore must implement the scratch trio.** SAML SP backs
`InResponseTo` single-use replay protection with
`MethodContext.methodScratch`, which requires the `SessionStore` to
implement `saveScratch` / `readScratch` / `deleteScratch`. The bundled
memory adapter and **all four production adapters** (Postgres, D1,
DynamoDB, Durable Object) implement it. For Postgres / D1 the
`openauth_scratch` table is created by the same `migrate()` call you
already run. If you wire a custom `SessionStore` that lacks the trio,
the `GET /authorize` handler fail-fasts with a clear error rather than
issuing an AuthnRequest whose request id is never cached (which would
make every assertion fail at the ACS with an opaque message).

**Per-tenant config shape** (`MethodConfig.config`, validated by
`samlSpFactory.configSchema`):

```ts
{
  id: "corp-saml",            // becomes part of the derived SP entityID + ACS URL
  kind: "saml-sp",            // factory lookup key — routes /<id>/* dispatch
  type: "custom",             // MethodType has no SAML member; routing is by `kind`
  enabled: true,
  config: {
    idp: {
      entityId: "https://corp-idp.example/saml/metadata", // IdP EntityID
      ssoUrl: "https://corp-idp.example/sso",              // IdP SSO endpoint
      nameIdFormat: "persistent",                          // optional request hint
      // ≥1 PEM signing cert. Multiple + notBefore/notAfter windows
      // enable hot rotation with no redeploy.
      signingCerts: [
        { pem: "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----" },
      ],
    },
    attributeMapping: { /* see cookbook below */ },
    clockSkewSeconds: 60,     // default 60; allowance on NotBefore/NotOnOrAfter
  } satisfies SamlSpConfig,
}
```

The assertion must be signed; the outer `<Response>` need not be
(stricter would reject the Okta/Entra default).

**IdP-initiated SSO** (`idpInitiated`). Set this block to accept
unsolicited Responses (Okta tile, Entra "My Apps") at the **same** ACS
(`/cb/<methodId>` — a SAML SP has one ACS; the IdP posts solicited and
unsolicited there):

```ts
idpInitiated: {
  defaultClientId: "your-rp-client-id",          // must be a registered client
  defaultRedirectUri: "https://app.example/cb",  // must be in that client's redirectUris
  defaultScopes: ["openid", "email"],
}
```

Absent ⇒ unsolicited Responses stay `invalid_request` (the
conservative default). When present, an unsolicited signed assertion
mints a code and 302s to `defaultRedirectUri`; the framework
re-validates `defaultClientId`/`defaultRedirectUri` against the
registered client (open-redirect defence). `RelayState` is treated as
opaque — it is **never** a redirect target. Replay is handled by
assertion-ID dedup (there is no `InResponseTo` to single-use).

**Signed AuthnRequest** (`signAuthnRequest` + `signingKey`). Some IdPs
require it. The SP signing keypair is **per-connection config**, not a
KeyStore reference — the IdP pins this cert and rotation is an
IdP-coordination event, independent of OIDC token-key rotation:

```ts
signAuthnRequest: true,
signingKey: {
  privateKeyPem: "-----BEGIN PRIVATE KEY-----\n…",   // signs the AuthnRequest
  certPem: "-----BEGIN CERTIFICATE-----\n…",          // IdP pins this; metadata advertises it
}
```

`signingKey` is required when `signAuthnRequest` is `true` (schema-
enforced). `privateKeyPem` is a **secret**: it lives in
`MethodStore`-backed config, so encrypt that store at rest (or supply
it via your own resolver) — same handling as any per-tenant
credential. When signing is enabled, the SP metadata automatically
advertises `AuthnRequestsSigned="true"` and a signing `KeyDescriptor`,
so it stays truthful to runtime behaviour.

**Single Logout (front-channel SLO).** Set `idp.sloUrl` to enable it.
Two anonymous routes become active (gated on `idp.sloUrl` — absent ⇒
they are not served, and SP metadata advertises no
`SingleLogoutService`, so an IdP never sends a logout we cannot
complete):

```
GET|POST /m/<methodId>/sls       ← IdP LogoutRequest / LogoutResponse
POST     /m/<methodId>/logout    ← host-driven SP-initiated logout
```

- **IdP-initiated (receive).** The IdP delivers a signed
  `LogoutRequest` to `/sls` (HTTP-Redirect or HTTP-POST). The library
  verifies the XML-DSig against `idp.signingCerts` (node-saml — no
  hand-rolled crypto), replay-dedups the request `@ID`, emits a signed
  `LogoutResponse` 302 back to `idp.sloUrl`, and — *before* responding
  — fires your **`onLogout`** hook. Authenticity is the signature, not
  a cookie: a forged request gets a 403 and no side effect.
- **`onLogout` host hook** (top-level `IdPOptions.onLogout`, a sibling
  of `success`). The library cannot map a SAML `NameID` to your OIDC
  `subject` — that mapping lives in your `success` callback — so it
  hands you the verified logout and you decide:

  ```ts
  onLogout: async ({ tenant, methodId, nameId, sessionIndex }) => {
    await myApp.endSessionFor(nameId)          // your session teardown
    const subject = await myApp.subjectFor(nameId)
    return subject ? { revokeSubject: subject } : undefined
    // returning { revokeSubject } makes the library run the same
    // revokeAllForSubject that /end_session uses. Omit ⇒ no library
    // revocation (you handled it). A throw fails the SLO closed.
  }
  ```

  Absent ⇒ the library still verifies + acknowledges the logout and
  emits a `session_logout` audit event (`via: "upstream_slo"`), but
  revokes nothing (it cannot resolve the subject without you).

- **SP-initiated (send).** From your authenticated logout UX, `POST`
  to `/m/<methodId>/logout` with form fields `nameId` (required),
  `sessionIndex` / `relayState` (optional), and `nameIdFormat`
  (optional — one of `persistent` / `transient` / `emailAddress` /
  `unspecified`; an unrecognized value is refused, not passed
  through). The
  library emits a (signed iff `signingKey`) `LogoutRequest` 302 to
  `idp.sloUrl`; the IdP's `LogoutResponse` returns to `/sls`. This is
  **pure protocol propagation — it does not revoke library tokens**:
  OIDC token/session termination stays `/end_session`'s job (call
  both from your logout flow). **Security:** this route is anonymous
  at the library boundary and emits a signed `LogoutRequest` for
  whatever `nameId` you post, so you MUST only invoke it for the
  authenticated subject, with that subject's own `NameID`, behind your
  own CSRF protection. Forced-logout is a host-owned risk — the
  library cannot authenticate the caller without owning a session it
  deliberately does not. Back-channel (SOAP) SLO is not supported.

**Encrypted assertions** (`allowEncryptedAssertions` + `decryptionKey`).
Off by default. Opt in per connection when the IdP encrypts the
assertion:

```ts
allowEncryptedAssertions: true,
decryptionKey: {
  privateKeyPem: "-----BEGIN PRIVATE KEY-----\n…",  // decrypts the assertion
  certPem: "-----BEGIN CERTIFICATE-----\n…",         // IdP encrypts to this; metadata advertises it
}
```

`decryptionKey` is required when `allowEncryptedAssertions` is `true`
(schema-enforced) and `privateKeyPem` is a **secret** (same at-rest
handling as `signingKey.privateKeyPem`). The decrypted assertion's
XML-DSig is still **fully enforced** — encryption does not relax
signature verification. With the flag off (or no `decryptionKey`), an
encrypted assertion is rejected with an operator-legible reason. SP
metadata advertises a `use="encryption"` `KeyDescriptor` iff this is
configured, so the IdP knows which cert to encrypt to.

**Configuring the IdP side (manual — no metadata importer yet).** Both
values the host registers at the IdP are *derived*, not configured, so
they are stable across deploys:

- **SP EntityID / Audience** = `<issuerUrl>/<tenantId>/<methodId>`
  (trailing slash on `issuerUrl` is stripped). E.g. issuer
  `https://idp.acme.com`, tenant `acme`, method `corp-saml` →
  `https://idp.acme.com/acme/corp-saml`.
- **ACS URL** (Assertion Consumer Service, HTTP-POST binding) =
  `<issuerUrl>/cb/<methodId>` — the framework's universal callback,
  e.g. `https://idp.acme.com/cb/corp-saml`.

In the IdP admin console: set the SP EntityID and ACS URL to those two
values, choose the HTTP-POST binding for the assertion, then populate
`config.idp` from the IdP's metadata. The subpath exports a pure
`parseSamlIdpMetadata` helper so a console can accept a pasted metadata
XML / URL instead of hand-copying fields:

```ts
import { parseSamlIdpMetadata } from "@_mustachio/openauth/methods/saml-sp"

const parsed = parseSamlIdpMetadata(metadataXml)
if (!parsed.ok) {
  // parsed.error.code === "invalid_request" — show parsed.error.description
} else {
  // parsed.value is the SamlIdpConfig.idp shape:
  //   { entityId, ssoUrl, sloUrl?, nameIdFormat?, signingCerts: [{ pem }] }
  // Persist it as config.idp on the method instance.
}
```

It returns a `Result` (never throws), is namespace-prefix agnostic
(Okta `md:`, Entra default-ns, ADFS — all parse), normalises
`X509Certificate` bodies into PEM, and rejects SP metadata or any
document missing an `IDPSSODescriptor` / signing cert / `entityID`.
`attributeMapping` is still authored by hand — it is a per-deployment
policy decision, not data the IdP publishes.

**The reverse direction — publishing *our* SP metadata.** Most IdPs
also accept an SP metadata URL/file instead of hand-entered EntityID +
ACS. The library serves it, **unauthenticated**, at:

```
GET /m/<methodId>/metadata        → application/samlmetadata+xml
```

No `idp.flow` cookie, no session — paste this URL straight into the
IdP admin console. The document's `entityID` and ACS `Location` are
derived from the *same* logic the live AuthnRequest/ACS path uses, so
they cannot drift from what the runtime actually accepts (a CI test
asserts this equality). It advertises `WantAssertionsSigned="true"`,
the HTTP-POST ACS, and `NameIDFormat` iff `config.idp.nameIdFormat` is
set. Every other element is **truthful to runtime config** — emitted
only when the corresponding capability is actually enabled, so the
metadata never advertises something the SP cannot honour:

- `AuthnRequestsSigned="true"` + a `use="signing"` `KeyDescriptor`
  iff `signAuthnRequest` + `signingKey` (else
  `AuthnRequestsSigned="false"`, no descriptor);
- a `use="encryption"` `KeyDescriptor` iff `allowEncryptedAssertions`
  + `decryptionKey`;
- `SingleLogoutService` (HTTP-Redirect **and** HTTP-POST, same-host
  as the ACS) iff `idp.sloUrl` is configured.

Served with `Cache-Control: s-maxage=300`.

Mechanically this is the first user of the framework's general
`publicRoutes` opt-in (a method declares which route keys are
anonymous); it is not SAML-specific HTTP surface — see
`ARCHITECTURE.md` § `publicRoutes`.

**Attribute-mapping cookbook.** `attributeMapping` normalizes the
verified assertion into `providerSubject` + the property fields handed
to your `success(input)` callback. Each ref is either the assertion's
NameID or a named SAML attribute:

```ts
attributeMapping: {
  // providerSubject. Defaults to NameID if omitted — the usual choice
  // for `persistent` NameIDs.
  subject: { source: "nameId" },

  // Standard single-valued attributes. `name` is the SAML Attribute
  // Name exactly as the IdP emits it (Okta and Entra differ — Entra
  // tends to emit the long claim URIs).
  email: { source: "attribute", name: "email" },
  name:  { source: "attribute", name: "displayName" },

  // SAML assertions are issued post-IdP-verification, so email is
  // effectively verified. This is a literal, not an attribute lookup.
  emailVerified: { source: "literal", value: true },

  // Multi-valued — array shape is preserved.
  groups: { source: "attribute", name: "groups" },

  // `format` disambiguates when an IdP emits the same Name twice with
  // different NameFormats.
  custom: {
    department: {
      source: "attribute",
      name: "http://schemas.example/department",
      format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
    },
  },
}
```

Anything not covered by the standard slots goes under `custom` — there
is no need to fork the method per IdP. `groups` (and any multi-valued
attribute) arrives as a string array in
`SamlSpProperties.attributes`; single-valued attributes arrive as
strings. The host owns the final `SubjectClaim` mapping in `success`,
exactly as with OAuth/OIDC.

**Requesting MFA (`requestedAuthnContext`).** By default **no
`<RequestedAuthnContext>` is sent**, which lets the IdP apply its own
sign-on policy — the right behaviour for nearly every connection. Set
this only when the IdP has told you which class refs it honours:

```ts
requestedAuthnContext: {
  classRefs: ["urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthn"],
  comparison: "minimum",   // default "exact"
}
```

Be deliberate here. A `RequestedAuthnContext` the IdP cannot satisfy is
answered with `NoAuthnContext` rather than a login, and `"exact"` is an
easy way to produce that — an IdP that ran MFA does not match a request
for plain `PasswordProtectedTransport`. `"minimum"` is usually the safer
choice when the goal is "at least MFA."

Requesting a context does not verify one was used. Read
`SamlSpProperties.authnContextClassRef` for what the IdP actually
asserted, and make step-up decisions on that:

```ts
success: async (input) => {
  const ctx = input.properties.authnContextClassRef
  const mfa = ctx?.endsWith(":MultiFactorAuthn") ?? false
  // …record `mfa` on your session, gate sensitive routes on it
}
```

**Forcing re-authentication (`forceAuthn`).** `forceAuthn: true` sets
`ForceAuthn="true"` on the AuthnRequest, asking the IdP to
re-authenticate even if it has a live session. It is a *request*: SAML
obliges the IdP to nothing and the Response carries no proof either way,
so never treat a successful assertion as evidence of fresh
authentication.

**Aligning session lifetime (`sessionNotOnOrAfter`).** When the IdP
supplies `AuthnStatement/@SessionNotOnOrAfter`, it is surfaced as a Unix
ms timestamp on `SamlSpProperties`. The library does not act on it —
token and session lifetimes are host policy, and this library owns no
session. If you want "when their IdP session ends, ours ends," clamp
your own session/token TTL to it in `success`.

**Adopting an existing entityID (`spEntityId`).** The SP entityID is
derived as `<issuerUrl>/<tenantId>/<methodId>` — stable and zero-config.
Override it only to adopt an entityID that already exists at the IdP, so
a customer can migrate an existing SAML app without editing their
production SSO config:

```ts
spEntityId: "https://legacy-sp.example/saml/sp",
```

The override flows to everything at once — AuthnRequest issuer, audience
validation, SP metadata, logout messages — so the published metadata
stays truthful. Changing it on a live connection invalidates the
IdP-side trust config; treat it as an IdP-coordination event.

**Signature posture (`requireSignedAssertion` / `requireSignedResponse`).**
The defaults (`true` / `false`) are correct for Okta, Entra, and the
large majority of IdPs: the assertion carries the identity, conditions,
and audience, so signing *it* is what binds them. Two reasons to change
them:

```ts
requireSignedResponse: true,               // defence in depth, both signed
// or, for an IdP that signs ONLY the Response:
requireSignedAssertion: false,
requireSignedResponse: true,
```

Turning both off is rejected by the config schema — an unsigned
assertion inside an unsigned Response is unauthenticated XML. When
`requireSignedAssertion` is `false`, SP metadata advertises
`WantAssertionsSigned="false"` so it keeps stating actual behaviour.

#### Generating the SP keypair

`signingKey` and `decryptionKey` each need a PEM private key and a
matching self-signed X.509 certificate. Node's standard library cannot
produce an X.509 certificate — it generates keypairs, not certs — so
this is an `openssl` step you run once per connection and store with the
rest of the connection's config:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout sp-signing-key.pem \
  -out    sp-signing-cert.pem \
  -days   1095 \
  -subj   "/CN=idp.example SAML SP"
```

- **`-nodes` is required.** A passphrase-protected key cannot be loaded
  from config; the PEM must be unencrypted at rest in the process. Keep
  it secret the same way you keep any per-tenant credential — encrypt
  the `MethodStore` at rest, or supply it through your own resolver.
- **RSA 2048 or better.** Some IdPs still reject EC keys for SAML.
- **Long validity.** Expiry forces a coordinated swap (below), so a
  3-year cert is normal here rather than lax.
- **The `CN` is cosmetic.** SAML pins the certificate by value; nothing
  validates it as a chain or checks the subject. Use something you will
  recognise in an IdP admin console.
- **Use separate keypairs for signing and decryption.** They are pinned
  independently at the IdP and rotated on different occasions.

**SP cert rotation is a coordinated swap, not a hot rotation.** SP
metadata advertises exactly one signing certificate, and the IdP pins
it, so there is no overlap window on this side: generate the new pair,
update `signingKey`, and have the IdP admin re-import your metadata (or
paste the new cert) in the same change. Plan it as a maintenance
window with the customer. This is deliberately asymmetric with IdP
certs, which *do* rotate hot — see below.

#### Keeping IdP signing certs fresh

`idp.signingCerts` accepts several PEMs, each with an optional
`notBefore` / `notAfter` window, and the verifier accepts any cert whose
window covers now. That is what makes IdP-side rotation survivable
without a redeploy — but nothing refreshes the list for you. The library
deliberately performs no I/O: `parseSamlIdpMetadata` is pure, and
fetching is the host's job.

Without a refresh loop the failure mode is a bad morning: the customer
rotates their IdP certificate and every login breaks at once. Poll the
connection's metadata URL on a schedule (daily is plenty) and merge:

```ts
import { parseSamlIdpMetadata } from "@_mustachio/openauth/methods/saml-sp"
import type { SamlIdpSigningCert } from "@_mustachio/openauth/methods/saml-sp"

/** How long a retired cert keeps verifying after the IdP drops it. */
const OVERLAP_MS = 7 * 24 * 60 * 60 * 1000

function mergeSigningCerts(
  current: ReadonlyArray<SamlIdpSigningCert>,
  incoming: ReadonlyArray<SamlIdpSigningCert>,
  now: number,
): SamlIdpSigningCert[] | null {
  const has = (list: ReadonlyArray<SamlIdpSigningCert>, pem: string) =>
    list.some((c) => c.pem.trim() === pem.trim())
  const added = incoming.filter((c) => !has(current, c.pem))
  if (added.length === 0) return null // nothing changed

  return [
    // Certs the IdP dropped get an expiry rather than deletion, so an
    // assertion signed moments before the change still verifies.
    ...current.map((c) =>
      has(incoming, c.pem) || c.notAfter !== undefined
        ? c
        : { ...c, notAfter: now + OVERLAP_MS },
    ),
    // New certs are active immediately — the IdP may cut over at any
    // moment, and it does not tell you when.
    ...added,
  ]
}

async function refreshIdpCerts(tenantId: string, methodId: string) {
  const stored = await myConfigStore.readSamlConnection(tenantId, methodId)

  const res = await fetch(stored.metadataUrl)
  if (!res.ok) return // transient — keep what works, try again tomorrow
  const parsed = parseSamlIdpMetadata(await res.text())
  if (!parsed.ok) return // malformed feed must never clobber a good config

  const merged = mergeSigningCerts(
    stored.config.idp.signingCerts,
    parsed.value.signingCerts,
    Date.now(),
  )
  if (!merged || merged.length === 0) return // never write an empty set

  await myConfigStore.writeSamlConnection(tenantId, methodId, {
    ...stored.config,
    idp: { ...stored.config.idp, signingCerts: merged },
  })
}
```

Three rules matter more than the exact code:

1. **Append, never replace.** Overwriting the list at the moment you
   notice a change breaks in-flight logins signed by the outgoing key.
2. **Every failure path keeps the existing config.** A network blip or a
   malformed feed must not be able to empty `signingCerts` — an empty
   active set fails every login with a configuration error.
3. **Retire on a timer, not on sight.** Give dropped certs a `notAfter`
   in the future rather than deleting them, and let them age out.

Note that only `signingCerts` is safe to merge automatically. A changed
`entityId` or `ssoUrl` means the IdP has been reconfigured, not rotated
— surface that to an operator instead of applying it.

---

## 9A. SCIM 2.0 — automated user provisioning

SCIM is the companion to SAML in enterprise deals: SAML lets people log
in, SCIM keeps the directory in sync — created on hire, updated on
change, **deactivated on termination**. The deprovisioning half is the
one customers audit.

Direction is inbound, like SAML SP: the customer's Okta or Entra calls
you. The library never pushes users anywhere.

**The library owns the protocol; you own the data.** Routing, bearer
auth, schema validation, PATCH normalization, the error envelope,
pagination and the discovery documents are handled here. Every read and
write goes through a `ScimDirectory` you implement against your own
tables. **No user data is stored in the library** — it has no user
model, by design.

### Wiring it up

```ts
import { createIdP, type ScimDirectory } from "@_mustachio/openauth"

const scimDirectory: ScimDirectory = {
  async getUser(tenantId, id) { /* … */ },
  async findUsers(tenantId, query) { /* … */ },
  async createUser(tenantId, user) { /* … */ },
  async replaceUser(tenantId, id, user) { /* … */ },
  async patchUser(tenantId, id, patch) { /* … */ },
  async deleteUser(tenantId, id) { /* … */ },
}

const idp = createIdP({ /* … */, scimDirectory })
```

Omit `scimDirectory` and `/scim/v2/*` answers `501` regardless of
per-tenant config — SCIM is opt-in for the whole deployment.

Then enable it per tenant, with a bearer token you mint and hand to the
IdP admin. Hash it exactly like a client secret; never store the raw
value:

```ts
import { hashClientSecret } from "@_mustachio/openauth"

const token = crypto.randomUUID() + crypto.randomUUID() // show once
tenant.scim = { enabled: true, tokenHash: await hashClientSecret(token) }
```

In Okta or Entra, the connector wants the base URL `https://your-issuer/scim/v2`
and that token as the bearer.

### What the endpoints do

```
GET    /scim/v2/ServiceProviderConfig | /ResourceTypes | /Schemas
GET    /scim/v2/Users                 — filter + pagination
POST   /scim/v2/Users
GET|PUT|PATCH|DELETE /scim/v2/Users/{id}
GET    /scim/v2/Groups                — filter + pagination
POST   /scim/v2/Groups
GET|PUT|PATCH|DELETE /scim/v2/Groups/{id}
```

Groups are covered below and are opt-in.

### Four things worth knowing

**0. Unknown attributes are skipped, not rejected.** An attribute this
library does not model — `title`, `nickName`, `locale` — is dropped from
both writes and patches rather than failing the request. Okta pushes
several of them in the same `PatchOp` as `active`, and failing the whole
request over one would take the deactivation with it.

**1. `patchUser` is where deprovisioning happens.** Okta and Entra
normally deactivate with `PATCH {active: false}` rather than `DELETE`.
Getting that one operation right matters more than everything else here.

The library resolves every spelling — Okta's pathless
`{op:"replace", value:{active:false}}`, Entra's
`{op:"Replace", path:"active", value:"False"}` (yes, the boolean arrives
as a string), and targeted paths like `emails[type eq "work"].value` —
into a flat delta:

```ts
async patchUser(tenantId, id, patch) {
  // present ⇒ set to this, null ⇒ clear, absent ⇒ leave alone.
  // Values are fully resolved: `patch.emails` is the complete new list,
  // never a fragment, and no SCIM path expression reaches you.
}
```

**2. `DELETE` is not deactivation.** The library will not quietly turn a
destructive request into a soft one — that would erase the distinction
in your audit trail. If you don't want cascading deletes, implement
`deleteUser` as a tombstone deliberately and write it down.

**3. `totalResults` must be the full match count**, not the size of the
page you return. Okta drives its paging loop off it, so returning the
page length makes the import loop or stop early. `startIndex` is 1-based.

**4. You own uniqueness.** The library stores no rows, so it cannot
enforce that `userName` is unique. Return
`err(authError.conflict("…", "userName"))` and it becomes a `409` with
`scimType: "uniqueness"`. Use a real database constraint rather than
check-then-write: Okta's initial import is heavily concurrent and will
find the race.

**Which error you return decides whether a failure gets fixed.** SCIM
clients retry `5xx` and give up on `4xx`, so:

| Return | Becomes | Use it for |
| --- | --- | --- |
| `authError.conflict(…)` | `409 uniqueness` | A collision only you can detect |
| `authError.invalidRequest(…)` | `400 invalidValue` | A **permanent** rejection you will never accept |
| anything else | `500` | A transient fault worth retrying |

The middle row matters most for groups. An IdP's group push can name a
member its user push filtered out, or one deleted between operations. If
you return a generic error there, the IdP retries the same doomed
request indefinitely; return `invalidRequest` and it stops and shows an
admin what is wrong. Your message is passed through on both `4xx` paths
— it is what appears in the provisioning log, so make it specific.

Reserve `500` for genuinely transient problems. It is the right answer
there: retrying beats reporting a success for a write that never
happened.

### Filter support is deliberately narrow

RFC 7644's filter grammar is large; Okta and Entra use a sliver of it.
Supported:

```
userName eq "…"    externalId eq "…"    id eq "…"    active eq true|false
emails[type eq "work"].value eq "…"     <term> and <term>
```

Anything else gets a `400` naming what works, rather than a silently
wrong result. The parsed filter reaches your port as a small typed tree
(`ScimFilter`), never as a string — you never write a filter parser.

If a real connection needs something outside this set, the `400` will
say so immediately; widen it then, on evidence.

### Groups (optional)

Group provisioning is opt-in as a **set**: implement all six group
methods on `ScimDirectory` or none. Omit them and `/scim/v2/Groups`
answers `501`, and the discovery documents leave the Group resource type
out entirely — a client is never told a resource works when it does not.

Membership is the one place the library does *not* resolve a patch into
a final value, and the reason is size. A user's email list is small; a
group's membership is not. Resolving "add one member" against a
20,000-member group would mean reading all 20,000 rows and writing them
back on every change. So your port receives the client's intent:

```ts
async patchGroup(tenantId, id, patch) {
  if (patch.members) {
    // Full replace — exactly this membership, nothing else.
  } else {
    // Incremental — one insert / one delete, not a rewrite.
    patch.addMembers    // [{ value, display? }]
    patch.removeMembers // ["userId", …]
  }
}
```

The two forms are mutually exclusive: a full replace in the same request
absorbs any add or remove alongside it, so you never receive `members`
together with the incremental fields and need no ordering rule.

**Make membership operations idempotent.** Adding an existing member or
removing an absent one must succeed quietly. IdPs retry, and a `4xx`
there stalls a group push indefinitely.

**Honour `excludeMembers`.** When a client sends
`excludedAttributes=members` — Okta does while enumerating groups —
`ScimGroupQuery.excludeMembers` is `true` and you should skip loading
membership entirely. Ignoring it turns a cheap listing into a fan-out
read per group. Return the record with `members` **omitted**, not `[]`:
an empty array tells the client the group has been emptied.

### Consistency requirement

`ScimDirectory` needs **read-your-writes**. A SCIM client will
`GET /Users?filter=userName eq "…"` immediately after creating a user to
confirm the create; an eventually-consistent read there causes duplicate
users, which is the classic SCIM failure and unpleasant to unpick. See
`src/ports/CONSISTENCY.md`.

---

## 10. Subject identity & JWT validation in your services

Access tokens are JWTs (ES256). Your downstream services validate them
against `/.well-known/jwks.json`:

```ts
import { jwtVerify, createRemoteJWKSet } from "jose"

const JWKS = createRemoteJWKSet(
  new URL("https://auth.yourapp.com/.well-known/jwks.json"),
)

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
# Authorize lifecycle
authorize_started, authorize_succeeded, authorize_failed,
flow_replay_attempt, flow_tenant_mismatch, flow_callback_mismatch,
unrecoverable_flow,

# Token lifecycle
token_issued, token_refreshed, token_exchanged, token_revoked,
refresh_reuse_detected,

# Config / method loading
factory_id_mismatch, invalid_method_config, unknown_method_kind,

# OIDC + DPoP (Phase 8 Session 2)
session_logout,         # OIDC RP-Initiated Logout 1.0
dpop_replay_detected,   # RFC 9449 §11.1

# Host-emitted
custom
```

`token_issued` additionally carries optional `idTokenIssued` and
`dpopBound` boolean flags so dashboards can filter by feature without
re-parsing the access token.

---

## 12. Client-secret hashing

When you store `secretHash` in `ConfigStore`, hash the plaintext with
SHA-256 + base64url:

```ts
// Match exactly what the library does at verification time:
function hashClientSecret(plain: string): string {
  const bytes = new TextEncoder().encode(plain)
  return Buffer.from(
    crypto.createHash("sha256").update(bytes).digest(),
  ).toString("base64url")
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
  returns `200` with an empty body (RFC 7009 §2.2 — indistinguishable
  from an unknown-token revoke so callers cannot probe token existence
  across clients). The attempt is audited as
  `kind: "custom", type: "revoke_wrong_client_attempt"`.
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
- **Cookie defaults are `secure: true`, no domain, `path: "/"`.** For
  local-HTTP development pass `createIdP({ cookies: { secure: false } })`
  so `idp.flow` and other framework cookies round-trip on `localhost`
  (Chrome rejects `Secure` cookies over plain HTTP). `cookies.domain` /
  `cookies.path` are passed through to every framework-issued cookie
  that doesn't override them.

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
  to verify _before_ the tenant is loaded; per-tenant keys create a
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

> **⚠️ Rate-limiting is required, not optional.**
>
> The library applies **no rate limits** at any endpoint. The
> high-traffic unauthenticated endpoints — `/authorize`, the per-method
> credential routes (`/<methodId>/login`, `/<methodId>/code/verify`,
> `/<methodId>/passkey/*`), `/token`, `/revoke`, `/introspect`, and the
> picker — are exposed without protection. Deploying the IdP without an
> upstream rate-limiting layer leaves you open to credential stuffing,
> code-verification brute force, refresh-token harvesting, and OIDC
> discovery scraping. **Until the rate-limiter port lands, deploy
> behind a rate-limiting proxy / CDN / WAF.** Per-IP buckets for
> unauthenticated endpoints and per-client buckets for `/token` are the
> usual minimum.

- **mTLS client auth (RFC 8705)** — relies on a host-side
  `extractClientCert(req)` hook that doesn't exist yet.
- **Rate-limiter port** — see the callout above. Until this lands, the
  library has no defense against high-volume abuse on its
  unauthenticated endpoints.
- **Logger / Tracer ports** — wrap `idp.handle` with your own
  request-logging middleware until structured ports land.

### What landed in Phase 8 Session 2

The OIDC issuance + standards features below are **shipped** and
documented in §15a–e below:

- **OIDC `id_token` issuance** with `nonce`, `auth_time`, `at_hash`,
  `amr`, scope-gated profile claims. Refresh-grant reissue with stable
  `auth_time`.
- **`/end_session`** (OIDC RP-Initiated Logout 1.0) — id_token_hint
  verify, post_logout_redirect_uri validation, subject revocation.
- **PAR** (RFC 9126) — `/par` endpoint, `request_uri` rehydrate,
  per-client `requirePushedAuthorizationRequests` enforcement.
- **DPoP** (RFC 9449) — sender-constrained tokens; `cnf.jkt` on
  access tokens; refresh-bound rotation; `/userinfo` proof matching;
  jti replay protection.
- **`claims` parameter** (OIDC Core §5.5) — additive claim grant
  bypassing scope gating for id_token + `/userinfo`; preserved across
  refresh rotation.
- **Pairwise subjects** (§8.1) — per-client `sectorIdentifier`.
- **Dynamic Client Registration** (RFC 7591) — host-hook driven
  `/register` endpoint.

### 15a. OIDC `id_token` issuance

When an RP requests `scope=openid`, the `/token` response includes an
`id_token` alongside the access token:

```ts
const tokens = await fetch("https://idp.example/token", {
  method: "POST",
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: "rp-1",
    redirect_uri: "https://app.example/callback",
    code_verifier,
  }),
}).then((r) => r.json())
// tokens.id_token is a signed JWT carrying iss, sub, aud=client_id,
// exp, iat, auth_time, optional nonce, at_hash, amr, and §5.1 profile
// claims gated by granted scopes.
```

`auth_time` is stamped at end-user authentication and remains stable
across refresh-grant rotations (OIDC Core §12). `nonce` is echoed
verbatim from the `/authorize` request and is **NOT** carried forward
on refresh.

Scope→claim mapping follows OIDC Core §5.4 exactly:

- `profile` → `name`, `given_name`, `family_name`, `preferred_username`,
  `picture`, `locale`, etc.
- `email` → `email`, `email_verified`.
- `phone` → `phone_number`, `phone_number_verified`.
- `address` → `address` (structured object).

Populate the values in your `success` callback's
`SubjectClaim.properties`; the framework picks up only the names that
match the granted scopes.

**Custom vendor scopes.** Use `IdPOptions.customScopeClaims` to expose
host-specific identity vocabulary alongside the §5.4 mapping:

```ts
createIdP({
  // ...
  customScopeClaims: {
    tenant: ["tenant_id", "tenant_role", "tenant_roles"],
    org: ["organization_id", "org_role"],
  },
})
```

The keys are added to discovery's `scopes_supported`; the union of
values is added to `claims_supported`. A client requesting
`scope=openid tenant` will receive `tenant_id` / `tenant_role` /
`tenant_roles` in the id_token AND `/userinfo` — sourced from
`SubjectClaim.properties` like the standard claims.

The standard §5.4 mapping always wins on key collision: an entry for
`email` is silently ignored, so a custom scope can never quietly
redefine what `email` grants. A client must list a custom scope in
`ClientConfig.scopes` to be allowed to request it (the existing
per-client allowlist applies unchanged).

> ⚠️ Note: id_token claims are baked in at mint time; `/userinfo`
> reads `customScopeClaims` from your IdP config at request time.
> Changing the map between issuance and userinfo means existing
> id_tokens carry the old shape while subsequent `/userinfo` calls
> reflect the new mapping. This is normal JWT immutability — clients
> caching id_token claims should re-fetch `/userinfo` after a config
> bump if they need agreement.

### 15b. `/end_session` (RP-Initiated Logout)

Register `postLogoutRedirectUris` on each `ClientConfig`:

```ts
const client: ClientConfig = {
  id: "rp-1",
  name: "Acme",
  type: "confidential",
  secretHash: await hashClientSecret(secret),
  redirectUris: ["https://app.example/cb"],
  grantTypes: ["authorization_code", "refresh_token"],
  scopes: ["openid", "email"],
  pkceRequired: true,
  postLogoutRedirectUris: ["https://app.example/post-logout"],
}
```

RP usage:

```
GET /end_session?
  id_token_hint=<previously-issued-id-token>
  &post_logout_redirect_uri=https://app.example/post-logout
  &state=optional-rp-state
```

The IdP validates the `id_token_hint` signature (expiry is tolerated
per spec — logout commonly follows expiry), validates
`post_logout_redirect_uri` against the registered list (exact match —
never substring; defends against open redirect), revokes the
identified subject's refresh tokens via `revokeAllForSubject`, emits a
`session_logout` audit event, and 302s back to the RP with `state`
echoed.

### 15c. PAR — Pushed Authorization Requests

PAR moves the `/authorize` parameter set off the front channel.
Confidential clients authenticate to `POST /par`; the IdP returns a
short-lived `request_uri` which the RP includes in `/authorize`:

```
POST /par
Authorization: Basic <id:secret>
Content-Type: application/x-www-form-urlencoded

response_type=code&client_id=rp-1&redirect_uri=...&scope=openid&...

→ HTTP 201
{
  "request_uri": "urn:ietf:params:oauth:request_uri:abc...",
  "expires_in": 60
}
```

Then:

```
GET /authorize?client_id=rp-1&request_uri=urn:ietf:params:oauth:request_uri:abc...
```

`request_uri` is **one-shot**: a second `/authorize` with the same URI
fails with `invalid_request`. To require PAR for a client:

```ts
const client: ClientConfig = {
  // ... as above
  requirePushedAuthorizationRequests: true,
}
```

Direct `/authorize` without `request_uri` is then rejected.

### 15d. DPoP — Sender-Constrained Tokens

A DPoP-aware RP generates an asymmetric keypair, signs a fresh proof
JWT on each request, and the IdP binds the issued access token's
`cnf.jkt` to the public key's RFC 7638 thumbprint:

```
POST /token
DPoP: <jwt-with-typ:"dpop+jwt",alg:"ES256",jwk:{...}; payload {htu, htm, iat, jti}>
Content-Type: application/x-www-form-urlencoded
...

→ {
  "token_type": "DPoP",
  "access_token": "<jwt-with-cnf-jkt>",
  "refresh_token": "<dpop-bound-opaque>",
  ...
}
```

Resource servers use `Authorization: DPoP <token>` plus a fresh proof
with `ath = base64url(sha256(access_token))`. Refresh-grant rotation
requires a matching proof — a mismatched key returns
`invalid_dpop_proof` without burning the refresh token. To require
DPoP for a client:

```ts
const client: ClientConfig = {
  // ... as above
  dpopRequired: true,
}
```

`/token` then refuses bearer-only requests with `invalid_dpop_proof`.

### 15e. Dynamic Client Registration (RFC 7591)

Provide the optional hook on `IdPOptions`:

```ts
createIdP({
  // ...
  registerClient: async ({ tenant, request }) => {
    // Validate against your own policy
    if (!request.client_name) {
      return err(authError.invalidRequest("client_name required"))
    }
    const id = `dyn-${randomUUID()}`
    const isPublic = request.token_endpoint_auth_method === "none"
    let secret: string | undefined
    let secretHash = ""
    if (!isPublic) {
      secret = randomBytes(32).toString("base64url")
      secretHash = await hashClientSecret(secret)
    }
    // Persist via your ConfigStore (host responsibility)
    await db.clients.insert({
      tenantId: tenant.id,
      id,
      name: request.client_name,
      type: isPublic ? "public" : "confidential",
      secretHash,
      redirectUris: request.redirect_uris,
    })
    return ok({
      client: {
        /* the ClientConfig you just persisted */
      },
      ...(secret ? { secret } : {}),
    })
  },
})
```

Absent hook → `/register` returns 400 `invalid_request: "dynamic
client registration is not enabled"`. Per-tenant policy (require
sector_identifier, restrict grant_types, throttle registration rate)
lives in the host hook, not the library.

All of these are designed to be **additive when they ship**: new
optional fields on `IdPOptions`, new optional methods on existing
ports. Integrating today does not require an overhaul to pick them up
later.

---

## 16. Third-party type leakage policy

The public API never reaches a `jose` / `hono` / `oauth4webapi` /
`@simplewebauthn/server` / `aws4fetch` type into a re-exported type.
Consumers that `file:`-link or `npm link` this package against their
own copy of those libraries will not hit duplicate-type errors.

What that means in practice:

- **`Oauth2Properties.idTokenClaims`** is `Record<string, unknown>`
  (not `JWTPayload`). Narrow with `typeof claims.sub === "string"` at
  the call site.
- **`IdP.handle` / `IdPOptions.resolveTenant`** take the global
  `Request` and return the global `Response` — never Hono's `Context`.
- **`AuthMethodFactory.configSchema`** is `v1.StandardSchema<unknown,
Cfg>` (Standard Schema v1), satisfied by Zod 3.24+, Zod 4, Valibot
  1.0+, Arktype 2.0+, Effect Schema, and any other validator that
  implements the spec.
- **`KeyStore` private key material** is `unknown` (the adapter
  decides what to put there); `publicJwk` is `Record<string, unknown>`.

The contract is enforced by
`test/types/public-api-no-thirdparty-leaks.test.ts`, which
type-checks under `tsconfig.test.json`. If you add a public re-export
that exposes a third-party type, the guard's specific-property probes
will fail under regression. To extend coverage, add new
`assertAssignable<…>(…)` lines or property-shape probes for the new
public type.

Library-internal modules (`adapters/**`, `domain/jwt.ts`,
`domain/crypto.ts`, `http/**`) are free to import third-party types
locally — the rule is only about what's reachable from `src/index.ts`.

## 17. Verifying your integration

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

## 18. Where to look in the codebase

| You want to understand                        | Read                                                |
| --------------------------------------------- | --------------------------------------------------- |
| The embedding contract                        | `ARCHITECTURE.md` § "Embedding pattern"             |
| Port consistency requirements                 | `src/ports/CONSISTENCY.md`                          |
| The phased build history + decisions          | `docs/plans/claude/idp-rebuild-plan.md`             |
| Public type shapes                            | `src/types/*.ts`                                    |
| What's expected of each port impl             | `test/ports/*.ts` (parameterized conformance suite) |
| Example end-to-end flow under memory adapters | `test/integration/full-flow.test.ts`                |
| Conformance behavior the library guarantees   | `test/conformance/oauth-2.1.test.ts`                |
