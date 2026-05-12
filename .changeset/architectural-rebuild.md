---
"@_mustachio/openauth": minor
---

Architectural rebuild — replaces the legacy `issuer({})` surface with a ports + adapters core.

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
