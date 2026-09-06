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
| `docs/plans/claude/saml-sp-plan.md`          | SAML 2.0 SP — decisions (SAML-AD1–AD8), conformance matrix, and why there is no SAML IdP role.                 |
| `docs/plans/claude/scim-plan.md`             | SCIM 2.0 — decisions (SCIM-AD1–AD9), the protocol/data split, conformance matrix.                              |

## Source tree

```
packages/openauth/
├── ARCHITECTURE.md
├── INTEGRATION.md
├── src/
│   ├── index.ts              # public entry — `createIdP`, type re-exports
│   ├── client.ts             # @_mustachio/openauth/client — RP-side helpers
│   ├── error.ts, pkce.ts
│   ├── types/                # public-surface types (idp, tenant, method, scim, ...)
│   ├── ports/                # port interfaces + CONSISTENCY.md
│   ├── domain/               # pure functions over ports (authorize, token, ...)
│   │   └── scim/             # SCIM protocol layer (filter, patch, resource, ...)
│   ├── http/                 # Hono adapter, schemas, middleware, handlers
│   ├── methods/              # auth methods + provider factories
│   │   ├── providers/        # 15 vendor factories (google, github, ...)
│   │   └── saml-sp/          # SAML 2.0 SP — Node-only subpath export
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
//   MethodStore, AuditLog, ScimDirectory
// + SCIM types: ScimConfig, ScimUserRecord/Write/Patch/Query,
//   ScimGroupRecord/Write/Patch/Query, ScimGroupMember, ScimPage, ScimFilter
// + mount helpers: mountedPath, mountPath — for custom methods that emit
//   their own URLs; see "Path-mounted deployments" below
import { createClient } from "@_mustachio/openauth/client"
// + storage adapters: @_mustachio/openauth/adapters/{memory,postgres,d1,
//   durable-object,dynamo,kv,kms}
import { samlSpFactory } from "@_mustachio/openauth/methods/saml-sp"
// SAML lives on its own **Node-only** subpath (xml-crypto needs node:crypto);
// the root entry never re-exports it, so edge builds stay clean. SCIM has no
// such constraint — it is JSON over HTTP and lives on the root entry.
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

## Path-mounted deployments

`issuerUrl` is the single source of truth for where the IdP is mounted.
The service always serves its own routes at its root (`/authorize`,
`/m/*`, `/cb/*`) and the proxy strips the prefix inbound — but every URL
the library **emits** is resolved on the public side of that proxy and
must carry it. Build those with `mountedPath(issuerUrl, path)` /
`callbackTarget(...)` in `src/domain/mount.ts`, never a path-absolute
literal. Do not add a `basePath` option; a second source could disagree
with `iss` and discovery.

`FlowRecord.callbackPath` is the one place that stays un-prefixed: it is
matched against the inbound request, which has already been stripped.

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
  `test/types/public-api-no-thirdparty-leaks.test.ts`. The SAML subpath
  has its own guard (`saml-sp-no-thirdparty-leaks.test.ts`).
- **SAML and SCIM are inbound only.** The library consumes SAML
  assertions and receives SCIM provisioning; it never issues assertions
  and never pushes users outward. Downstream apps speak the OIDC issuer.
  See `SAML-AD8` / `SCIM-AD1` — a standing decision, not an unbuilt
  feature.
- SCIM stores no user data: the protocol lives in the library, the
  persistence behind the host's `ScimDirectory` port (`SCIM-AD2`).

## Release

See `docs/release-process.md`.
