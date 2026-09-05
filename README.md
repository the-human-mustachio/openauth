# `@_mustachio/openauth`

A **server-side IdP library** for OAuth 2.1 / OIDC Core. Embed it inside
your host application — the host owns the console, the data model, and
RBAC; this library owns the identity endpoints, per-tenant isolation, and
the standards posture.

> 🚀 **In a hurry?** Jump to [**QUICKSTART.md**](QUICKSTART.md) — a
> 5-minute clone → install → run → verify path, with a dense
> rules-that-bite section for LLM agents.

- **Library, not a service.** Mounts inside your existing app. No
  separate admin HTTP surface; the host imports port adapters in-process.
- **Multi-tenant from day one.** `TenantId` is an opaque partition key.
  Encode whatever hierarchy you need (App × App-Tenant, workspace,
  deployment) into it inside your `resolveTenant`.
- **OAuth 2.1 / OIDC Core.** Authorization code + PKCE, refresh-token
  rotation with reuse detection, RFC 7009 revoke, RFC 7662 introspect,
  RFC 8693 token exchange, `/.well-known/openid-configuration`.
- **15 upstream provider factories** (Google, GitHub, Apple, Microsoft,
  Discord, Facebook, LinkedIn, Slack, Spotify, Twitch, X, Yahoo,
  JumpCloud, Keycloak, Cognito) plus generic `oauth2Factory` /
  `oidcFactory` for everything else.
- **Built-in credential methods.** Password (argon2id), email/SMS code,
  WebAuthn passkey, M2M client-credentials.
- **Enterprise SAML 2.0 (Service Provider).** Consume signed assertions
  from Okta, Entra, Ping or ADFS so corporate SSO terminates here and
  your apps keep speaking OIDC. SP- and IdP-initiated SSO, the full
  verification gauntlet, SP metadata, Single Logout, encrypted
  assertions. Node-only, on its own subpath, so edge builds stay clean.
- **SCIM 2.0 provisioning.** Users and groups pushed from the customer's
  IdP — created on hire, updated on change, deactivated on termination.
  The library owns the protocol; your `ScimDirectory` owns the data, so
  no user records are stored in the library.
- **Production storage adapters.** Postgres, DynamoDB, Cloudflare D1, KV,
  Durable Objects, AWS KMS (key wrapping), in-memory (dev / tests).
- **Runs anywhere a fetch handler runs.** Node, Bun, AWS Lambda,
  Cloudflare Workers. (SAML is the one exception — it needs Node, and
  lives behind a separate import so the root entry stays edge-clean.)

## Install

```bash
bun add @_mustachio/openauth hono jose
# Plus a storage adapter for your deployment target:
bun add postgres                                            # Postgres
bun add @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb      # DynamoDB
bun add @aws-sdk/client-kms                                 # KMS key wrap
# Cloudflare D1 / KV / Durable Objects need @cloudflare/workers-types.
```

Storage adapters live under `@_mustachio/openauth/adapters/<backend>`.
Hono is a peer dependency.

## Minimum viable integration

```ts
import postgres from "postgres"
import {
  createIdP,
  asTenantId,
  authError,
  err,
  ok,
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

const sql = postgres(process.env.DATABASE_URL!)
const exec = fromPostgresJs(sql)
await migrate(exec) // idempotent

const idp = createIdP({
  resolveTenant: async (req) => {
    const clientId = new URL(req.url).searchParams.get("client_id")
    if (!clientId) return err(authError.invalidRequest("missing client_id"))
    return ok(asTenantId(clientId))
  },
  stateKeys: loadStateKeyRing(), // 32-byte HMAC key ring
  configStore: new PostgresConfigStore({ exec }),
  tokenStore: new PostgresTokenStore({
    exec,
    keyStore: new PostgresKeyStore({ exec }),
  }),
  sessionStore: new PostgresSessionStore({ exec }),
  keyStore: new PostgresKeyStore({ exec }),
  methodStore: new PostgresMethodStore({ exec }),
  auditLog: new PostgresAuditLog({ exec }),
  issuerUrl: "https://auth.yourapp.com",
  methods: {
    password: passwordMethod({
      users: {
        /* findByEmail, create? */
      },
    }),
    google: googleFactory,
  },
  subjects: {
    user: z.object({ userId: z.string(), email: z.string().email() }),
  } satisfies SubjectSchema,
  success: async ({ providerSubject, properties }) => ({
    type: "user",
    properties: {
      userId: await db.users.upsert({ providerSubject }),
      email: (properties as { email?: string }).email ?? "",
    },
  }),
})

Bun.serve({ port: 3000, fetch: idp.handle })
```

That's a complete IdP: `/authorize`, `/token`, `/cb/*`, `/userinfo`,
`/revoke`, `/introspect`, `/.well-known/*` over Postgres with password +
Google sign-in.

Next steps:

- **5-minute path** (runnable example + rules for AI agents):
  [`QUICKSTART.md`](QUICKSTART.md)
- **Full embedding guide** — four host contracts, method
  configuration, mounting under a prefix, behavioral contracts,
  hardening: [`packages/openauth/INTEGRATION.md`](packages/openauth/INTEGRATION.md)
- **Architectural picture** — tenant recovery, flow lifecycle, port
  consistency, embedding pattern:
  [`packages/openauth/ARCHITECTURE.md`](packages/openauth/ARCHITECTURE.md)

## Relying-party client

The RP-side helper lives at a separate import path for tree-shaking:

```ts
import { createClient } from "@_mustachio/openauth/client"

const client = createClient({
  clientID: "my-client",
  issuer: "https://auth.yourapp.com",
})

// Server-side code flow:
const { url } = await client.authorize(redirectUri, "code")
// ... after the user returns with ?code=...
const tokens = await client.exchange(code, redirectUri)
const verified = await client.verify(subjects, tokens.access, {
  refresh: tokens.refresh,
})

// SPA / mobile (PKCE):
const { challenge, url } = await client.authorize(redirectUri, "code", {
  pkce: true,
})
const exchanged = await client.exchange(code, redirectUri, challenge.verifier)
```

## Repo layout

```
packages/openauth/   Library source — see its ARCHITECTURE.md / INTEGRATION.md
examples/            One minimal embedding example
www/                 Astro/Starlight docs site
docs/                Release process + rebuild plan
```

## License

MIT.
