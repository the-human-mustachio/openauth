# Claude Code Guidelines

Context for Claude Code when working in this repo.

## What this is

`@_mustachio/openauth` is a **server-side IdP library** that gets embedded
inside a larger host application. The host owns the console UI, the data
model (Users, Apps, Workspaces, App-Tenants), authorization (RBAC), and
admin mutations. This library owns OAuth 2.1 / OIDC Core endpoints,
per-tenant isolation, the auth-method registry, and the port + adapter
stack.

`Tenant` is **opaque** to the library — a partition key, not a business
concept. The library never parses it.

This boundary is non-negotiable. Do not reintroduce console / admin-API /
RBAC scope into the library. See "Why the library doesn't ship a console"
in `packages/openauth/ARCHITECTURE.md`.

## Authoritative docs (read these before non-trivial work)

| Document                                     | What it covers                                                                                                 |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `packages/openauth/ARCHITECTURE.md`          | Mental model, type layout, tenant recovery, flow lifecycle, embedding pattern, phase status.                   |
| `packages/openauth/INTEGRATION.md`           | End-to-end embedding guide for hosts: install, public API, adapters, the four host contracts, hardening rules. |
| `packages/openauth/src/ports/CONSISTENCY.md` | Consistency contracts for every port.                                                                          |
| `docs/plans/claude/idp-rebuild-plan.md`      | Phased rebuild plan — sequencing + decisions.                                                                  |

## Source tree

```
packages/openauth/
├── ARCHITECTURE.md
├── INTEGRATION.md
├── src/
│   ├── index.ts              # public entry — `createIdP`, type re-exports
│   ├── client.ts             # @_mustachio/openauth/client — RP-side helpers
│   ├── error.ts, pkce.ts
│   ├── types/                # public-surface types (idp, tenant, method, ...)
│   ├── ports/                # port interfaces + CONSISTENCY.md
│   ├── domain/               # pure functions over ports (authorize, token, ...)
│   ├── http/                 # Hono adapter, schemas, middleware, handlers
│   ├── methods/              # auth methods + provider factories
│   │   └── providers/        # 15 vendor factories (google, github, ...)
│   ├── adapters/             # concrete port impls
│   │   ├── memory/  postgres/  d1/  durable-object/
│   │   └── dynamo/  kv/       kms/
│   └── ui/                   # forms.ts, picker.ts — server-rendered defaults
├── script/                   # build, preview-ui
└── test/                     # unit / port-conformance / integration / conformance
```

## Public entry — at a glance

```ts
import { createIdP } from "@_mustachio/openauth"
// + types: IdP, IdPOptions, Result, AuthError, TenantId, TenantConfig,
//   ClientConfig, MethodConfig, SubjectSchema, SubjectClaim, StateKeyRing
// + method factories: passwordMethod, codeMethod, m2mMethod, passkeyMethod,
//   oauth2Factory, oidcFactory, buildOauth2Method, buildOidcMethod
// + 15 vendor factories: googleFactory, githubFactory, … cognitoFactory
// + port interfaces: ConfigStore, TokenStore, SessionStore, KeyStore,
//   MethodStore, AuditLog
import { createClient } from "@_mustachio/openauth/client"
// + storage adapters: @_mustachio/openauth/adapters/{memory,postgres,d1,
//   durable-object,dynamo,kv,kms}
```

The host calls `createIdP(opts)` and serves the returned `idp.handle` as
the fetch entrypoint. See `INTEGRATION.md` § 7 for the minimum-viable
integration.

## Dev commands

```bash
# From packages/openauth/
bun test                          # unit + integration + conformance
bun run build                     # ESM + .d.ts under dist/
bun run preview:ui                # local visual check of forms + picker

# From www/
bun run build                     # Astro/Starlight docs site
```

## Conventions

- TypeScript strict; ESM only.
- Domain functions return `Result<T, AuthError>` rather than throwing.
- The `id` / `kind` split: `MethodConfig.id` is the tenant-local instance
  id and routes URLs (`/<id>/*`); `MethodConfig.kind` is the factory
  lookup key. The `methods` map passed to `createIdP` MUST have keys
  equal to `factory.kind`.
- `ClientConfig` is a discriminated union — public clients carry
  `pkceRequired: true` as a literal; confidential clients carry a
  required `secretHash`.
- The public API never reaches a `jose` / `hono` / `oauth4webapi` /
  `@simplewebauthn/server` type. See `INTEGRATION.md` § 16 and
  `test/types/public-api-no-thirdparty-leaks.test.ts`.

## Release

See `docs/release-process.md`.
