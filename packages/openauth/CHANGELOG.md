# @\_mustachio/openauth

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
