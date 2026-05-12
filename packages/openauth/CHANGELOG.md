# @\_mustachio/openauth

## 0.9.0

### Minor Changes

- 717d53c: Architectural rebuild — replaces the legacy `issuer({})` surface with a ports + adapters core.

  **New public entry:** `createIdP(opts)` returns `{ handle }` for the host to serve as its fetch entrypoint. `createClient` is unchanged.

  **Library scope:** server-side IdP library embedded inside a host application. The host owns the console UI, the product data model, RBAC, and admin mutations. The library owns OAuth 2.1 endpoints, per-tenant isolation, the auth-method registry, and the port + adapter stack. See `packages/openauth/INTEGRATION.md` for the end-to-end embedding guide and `packages/openauth/ARCHITECTURE.md` for the mental model.

  **What's in:**

  - OAuth 2.1 code flow (PKCE required), refresh-token rotation with reuse detection (per-family revoke), `/revoke` (RFC 7009), `/introspect` (RFC 7662), `/userinfo`, `/token-exchange` (RFC 8693), `/.well-known/{openid-configuration,jwks.json,oauth-authorization-server}`.
  - Tenant as a per-request resolution function, not a URL segment. Tenant is opaque to the library — partition key, not business concept.
  - `AuthMethod` as data + handler functions (framework-agnostic). 15 OAuth/OIDC providers ported (google, github, apple, microsoft, discord, facebook, linkedin, slack, spotify, twitch, x, yahoo, jumpcloud, keycloak, cognito) plus password (argon2id), code, m2m, and passkey.
  - Per-port storage adapters: memory, postgres, d1, durable-object, dynamo, kv, kms.
  - 27/27 hand-built OAuth 2.1 + partial-OIDC conformance matrix green.
  - Hardened state envelope (global MAC key, MAC + tenant + nonce + host + path consistency check on every callback), encrypted auth-code payloads at rest, full audit log.

  **What's out (deferred to a later release):**

  - OIDC `id_token` issuance. The library is OAuth 2.1 complete and ships the OIDC framing (discovery doc, `/userinfo`, `nonce`/`prompt`/`ui_locales` parsing) but does not yet mint an `id_token` at `/token`. Third-party RPs that use OIDC client libraries (NextAuth, oidc-client-ts, AppAuth, MSAL) will not work until that lands. First-party RPs that read identity from the JWT access token's inlined `claim` are unaffected.
  - DPoP, PAR, mTLS hook, dynamic client registration, RP-initiated logout, `prompt` enforcement, `max_age` / `auth_time`.

  **Breaking:** every public symbol from `0.8.x` (`issuer`, the per-provider Hono modules, the legacy `Storage` interface) is removed. There is no shim. Hosts migrating from `0.8.x` should read `INTEGRATION.md` and treat this as a rewrite, not an upgrade.

## 0.8.1

### Rebuild

The library was rebuilt as a library-only IdP. The previous
`issuer({...providers, storage, subjects, success})` surface is replaced
by `createIdP(opts)`; provider modules, storage modules, and the JSX UI
have been removed in favor of:

- A layered architecture: `domain/` (pure functions over typed ports),
  `http/` (Hono adapter + Zod schemas), `ports/` (interfaces with
  documented consistency contracts), `adapters/` (memory, postgres, d1,
  durable-object, dynamo, kv, kms), `methods/` (auth methods + provider
  factories), `ui/` (minimal server-rendered forms + picker).
- A `Result<T, AuthError>` discipline through the domain layer — no
  throws, closed error taxonomy mapped to OAuth 2.0 codes.
- Multi-tenancy as an opaque partition key — `TenantId` is never parsed
  by the library; hosts encode their hierarchy into it.
- OAuth 2.1 / OIDC Core posture: PKCE enforced on every public client at
  the type level, refresh-token rotation with reuse detection and family
  revocation, RFC 7009 revoke, RFC 7662 introspect with audience checks,
  RFC 8693 token exchange.
- 15 vendor provider factories (Google, GitHub, Apple, Microsoft,
  Discord, Facebook, LinkedIn, Slack, Spotify, Twitch, X, Yahoo,
  JumpCloud, Keycloak, Cognito) plus generic `oauth2Factory` /
  `oidcFactory` for multi-tenant cases where each tenant brings its own
  issuer.
- Built-in credential methods: `passwordMethod` (argon2id),
  `codeMethod`, `passkeyMethod` (WebAuthn), `m2mMethod`
  (client_credentials).
- A reference `PasskeyCredentialStore` shipped for memory / Postgres /
  DynamoDB.
- A public-API third-party type-leakage guard
  (`test/types/public-api-no-thirdparty-leaks.test.ts`): no `jose`,
  `hono`, `oauth4webapi`, or `@simplewebauthn/server` types are
  reachable from `src/index.ts`.

The embedding contract is documented in
`packages/openauth/INTEGRATION.md` and
`packages/openauth/ARCHITECTURE.md`. The phased rebuild plan lives at
`docs/plans/claude/idp-rebuild-plan.md`.
