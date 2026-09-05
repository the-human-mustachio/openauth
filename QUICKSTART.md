# Quickstart

A 5-minute path to a running IdP — for human developers and LLM agents
both. Skim the [`For LLMs`](#for-llms-the-rules-that-bite) section even
if you're not one; the constraints there are easy to violate accidentally.

> **One-line orientation.** `@_mustachio/openauth` is a server-side
> **library** you embed in a host application. It owns OAuth 2.1 / OIDC
> Core endpoints, per-tenant isolation, and storage adapters. The host
> owns UI, RBAC, and the user/tenant data model. The boundary is
> non-negotiable — see [`packages/openauth/ARCHITECTURE.md`](packages/openauth/ARCHITECTURE.md)
> § "Embedding pattern".

---

## 1. Prerequisites

- **Bun ≥ 1.1** (Node 20 + npm/pnpm also work; commands below use Bun).
- **A Postgres URL** for the example (`postgres://localhost/openauth_dev`
  is fine; the bundled `migrate()` creates tables idempotently). Skip
  this if you only want to read code.

## 2. Run the bundled example

The runnable example is `examples/embed-postgres/`. It mirrors
[INTEGRATION.md § 7](packages/openauth/INTEGRATION.md#7-minimum-viable-integration-node--postgres)
verbatim and stands up password + Google sign-in over a single Postgres.

```bash
git clone https://github.com/the-human-mustachio/openauth
cd openauth
bun install                                              # workspace install
cd examples/embed-postgres
export DATABASE_URL='postgres://localhost/openauth_dev'
bun run start
```

Verify liveness:

```bash
curl http://localhost:3000/.well-known/openid-configuration | jq .
```

You should see a complete OIDC discovery document with `issuer`,
`authorization_endpoint`, `token_endpoint`, `jwks_uri`, and
`code_challenge_methods_supported: ["S256"]`.

That's it — every standards endpoint is now live:

```
/authorize    /token         /userinfo       /revoke      /introspect
/cb/*         /end_session   /par            /register    /.well-known/*
```

## 3. Drop it into your own app

The smallest legal `createIdP` call needs **eight** things. Six are
ports (storage), two are host contracts:

```ts
import {
  createIdP, asTenantId, authError, err, ok,
  passwordMethod, googleFactory,
  type SubjectSchema, type StateKeyRing,
} from "@_mustachio/openauth"
import {
  fromPostgresJs, migrate,
  PostgresAuditLog, PostgresConfigStore, PostgresKeyStore,
  PostgresMethodStore, PostgresSessionStore, PostgresTokenStore,
} from "@_mustachio/openauth/adapters/postgres"

const exec = fromPostgresJs(postgres(process.env.DATABASE_URL!))
await migrate(exec)
const keyStore = new PostgresKeyStore({ exec })

const idp = createIdP({
  // ── Host contracts ────────────────────────────────────────────
  resolveTenant: async (req) => {                       // (1) req → TenantId
    const clientId = new URL(req.url).searchParams.get("client_id")
    return clientId
      ? ok(asTenantId(clientId))
      : err(authError.invalidRequest("missing client_id"))
  },
  success: async ({ providerSubject, properties }) => ({ // (2) auth → subject
    type: "user",
    properties: { userId: providerSubject, email: (properties as any).email ?? "" },
  }),
  subjects: { user: z.object({ userId: z.string(), email: z.string().email() }) }
    satisfies SubjectSchema,

  // ── Ports (storage) ───────────────────────────────────────────
  configStore:  new PostgresConfigStore({ exec }),
  tokenStore:   new PostgresTokenStore({ exec, keyStore }),
  sessionStore: new PostgresSessionStore({ exec }),
  methodStore:  new PostgresMethodStore({ exec }),
  auditLog:     new PostgresAuditLog({ exec }),
  keyStore,

  // ── Cross-cutting ─────────────────────────────────────────────
  stateKeys: loadStateKeyRing(),       // 32-byte HMAC ring; see INTEGRATION § 6
  issuerUrl: "https://auth.yourapp.com",
  methods: { password: passwordMethod({ users: { findByEmail: … } }),
             google:   googleFactory },
})

Bun.serve({ port: 3000, fetch: idp.handle })
```

The full host-side embedding guide — the **four host contracts**
(`resolveTenant`, `ConfigStore`, `success`, `subjects`), method
configuration, hardening rules, deployment-target adapter matrix — lives
in [`packages/openauth/INTEGRATION.md`](packages/openauth/INTEGRATION.md).

## 4. Verify your wiring

Walk these in order; each exercises a different layer:

1. `GET /.well-known/openid-configuration` — discovery is valid JSON.
2. `GET /authorize?response_type=code&client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256`
   returns `302` with a `state` query param.
3. Walk a full password-method flow. `/token` returns
   `access_token` + `refresh_token`.
4. Validate the access token against `/.well-known/jwks.json` from a
   downstream service. Check `iss`, `aud`, `tid`, `sub`.
5. Refresh once. The old refresh token returns `invalid_grant` on its
   second use (rotation + reuse detection).
6. Revoke the refresh token. `auditLog` records `token_revoked`.

Each of these has a matching case in
`packages/openauth/test/conformance/oauth-2.1.test.ts` you can crib.

---

## For LLMs — the rules that bite

If you're an AI agent picking up work in this repo, internalise these
before generating code. Each one is a contract violation that humans
will catch in review.

### Hard architectural rules

1. **This is a library, not a service.** Do not add an `/admin/*`
   surface, console routes, RBAC, or user-management endpoints to
   `packages/openauth/`. Those are host concerns. See
   [`CLAUDE.md`](CLAUDE.md) and
   [`ARCHITECTURE.md` § "Embedding pattern"](packages/openauth/ARCHITECTURE.md).
2. **`TenantId` is opaque.** Never `.split(":")` it inside the library.
   The host encodes whatever hierarchy it wants (`appId:appTenantId`,
   workspace IDs, deployments) and the library treats it as a partition
   key only.
3. **No third-party types leak through the public API.** Nothing
   exported from `src/index.ts` may reach a `jose` / `hono` /
   `oauth4webapi` / `@simplewebauthn/server` type. Use
   `Record<string, unknown>` and let consumers narrow. Enforced by
   `test/types/public-api-no-thirdparty-leaks.test.ts`.
4. **Domain functions return `Result<T, AuthError>`, not throws.**
   `import { ok, err, isOk, isErr, authError } from "@_mustachio/openauth"`.

### Easy-to-miss invariants

- **`methods` map key === `factory.kind`.** `createIdP` throws on
  construction if they disagree. The key is the routing prefix
  (`/<id>/login`), the kind is the factory lookup.
- **`ClientConfig` is a discriminated union.** `PublicClientConfig`
  requires `pkceRequired: true` as the literal `true` (compile error
  otherwise). `ConfidentialClientConfig` requires `secretHash`
  (sha256+base64url of the secret).
- **Auth-code TTL is fixed at 60 s** by OAuth 2.1 BCP — the storage
  layer rejects larger TTLs.
- **Refresh-token reuse triggers family revocation.** Detected reuse
  within the 60 s window invalidates every token in the family.
- **Public-API never returns Hono `Context`.** `idp.handle` takes the
  global `Request` and returns the global `Response`.
- **Cookies default `secure: true`.** For HTTP localhost dev pass
  `createIdP({ cookies: { secure: false } })` or Chrome rejects the
  framework's flow cookies.
- **`TokenStore` + `SessionStore` need strong CAS.** Cloudflare KV is
  not acceptable for those two ports. See
  [`src/ports/CONSISTENCY.md`](packages/openauth/src/ports/CONSISTENCY.md).
- **`KeyStore` must wrap key material in production.** Pass a
  `KeyWrapper` (KMS-backed) to `PostgresKeyStore` / `DynamoKeyStore`,
  or use the `KmsKeyStore` adapter. Plaintext is dev-only.

### Public API at a glance

Everything an embedding host imports lives at exactly two paths:

```ts
// Library — server-side IdP
import {
  createIdP, asTenantId, authError, ok, err, isOk, isErr,
  // Built-in methods
  passwordMethod, codeMethod, m2mMethod, passkeyMethod,
  // Multi-tenant upstream factories
  oauth2Factory, oidcFactory,
  // 15 vendor factories
  googleFactory, githubFactory, appleFactory, microsoftFactory,
  discordFactory, facebookFactory, linkedinFactory, slackFactory,
  spotifyFactory, twitchFactory, xFactory, yahooFactory,
  jumpcloudFactory, keycloakFactory, cognitoFactory,
  // Domain primitives
  revokeAllForSubject, argon2idHasher,
  // Types (illustrative — see src/index.ts for the full set)
  type IdP, type IdPOptions, type TenantId, type TenantConfig,
  type ClientConfig, type SubjectSchema, type SubjectClaim,
  type StateKeyRing, type SuccessMapInput,
  type ConfigStore, type TokenStore, type SessionStore,
  type KeyStore, type MethodStore, type AuditLog,
} from "@_mustachio/openauth"

// Storage adapter — pick by deployment target
import { … } from "@_mustachio/openauth/adapters/postgres"   // or
import { … } from "@_mustachio/openauth/adapters/dynamo"     // or
import { … } from "@_mustachio/openauth/adapters/d1"         // or
import { … } from "@_mustachio/openauth/adapters/durable-object"
import { … } from "@_mustachio/openauth/adapters/kv"
import { … } from "@_mustachio/openauth/adapters/kms"
import { … } from "@_mustachio/openauth/adapters/memory"     // dev/tests

// RP-side client (separate path for tree-shaking)
import { createClient } from "@_mustachio/openauth/client"
```

The authoritative re-export list is
[`packages/openauth/src/index.ts`](packages/openauth/src/index.ts). If
a symbol isn't exported there, it isn't public.

---

## Where to go next

| You want to…                                   | Read                                                                                       |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Embed the library in a host app                | [`packages/openauth/INTEGRATION.md`](packages/openauth/INTEGRATION.md)                     |
| Understand the mental model + flow lifecycle   | [`packages/openauth/ARCHITECTURE.md`](packages/openauth/ARCHITECTURE.md)                   |
| See per-port consistency requirements          | [`packages/openauth/src/ports/CONSISTENCY.md`](packages/openauth/src/ports/CONSISTENCY.md) |
| Read a runnable steel-thread                   | [`examples/embed-postgres/`](examples/embed-postgres/)                                     |
| See the phased rebuild plan + design decisions | [`docs/plans/claude/idp-rebuild-plan.md`](docs/plans/claude/idp-rebuild-plan.md)           |
| Connect an enterprise SAML IdP                 | [`INTEGRATION.md` § 9.5](packages/openauth/INTEGRATION.md)                                 |
| Accept SCIM provisioning from Okta / Entra     | [`INTEGRATION.md` § 9A](packages/openauth/INTEGRATION.md)                                  |
| Crib from conformance tests                    | `packages/openauth/test/conformance/oauth-2.1.test.ts`                                     |
