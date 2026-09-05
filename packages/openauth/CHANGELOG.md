# @\_mustachio/openauth

## 0.13.1

### Patch Changes

- f9f5bc5: Fix SAML Single Logout over the HTTP-Redirect binding, which failed signature verification on newer runtimes.

  The redirect binding signs the raw query octets (OASIS SAML 2.0 Bindings §3.4.4.1), so verification must see the exact bytes the IdP signed. The `/sls` handler was obtaining them via `new URL(request.url).search`, which round-trips the query through whatever URL encoder the runtime ships. Whether that round-trip preserves bytes turns out to be a property of the runtime rather than of the request: it holds on Bun 1.1 and does not on Bun 1.4, where every inbound redirect-binding `LogoutRequest` was rejected with a signature failure. The HTTP-POST binding was unaffected, since it never touches the query string.

  The query is now sliced directly out of the request URL, with no encoder in the path.

  If you deploy SAML SLO on Bun 1.2 or later, inbound IdP-initiated logout over the redirect binding was broken before this release.

## 0.13.0

### Minor Changes

- 0ec7985: SAML SP interop hardening — authentication-context control, an entityID override, configurable signature posture, and richer `AuthnStatement` facts.

  **Behaviour change: `RequestedAuthnContext` is no longer sent by default.** Previously the outbound `AuthnRequest` inherited the underlying library's defaults and always carried `<RequestedAuthnContext Comparison="exact">` demanding `PasswordProtectedTransport`. An IdP running an MFA sign-on policy can answer that with `NoAuthnContext` instead of a login. The SP now sends no `RequestedAuthnContext` unless you ask for one, letting the IdP apply its own policy. If you relied on the old behaviour, set it explicitly.

  **What's new:**

  - **`requestedAuthnContext`** — request specific authentication context classes (e.g. MFA) with `classRefs` and an optional `comparison` (`exact` | `minimum` | `maximum` | `better`, default `exact`). `minimum` is usually the safer choice when the goal is "at least MFA".
  - **`SamlSpProperties.authnContextClassRef`** — what the IdP _actually_ asserted, read from the signed assertion. Requesting a context is not proof one was used; step-up decisions belong on this value.
  - **`forceAuthn`** — sets `ForceAuthn="true"` on the `AuthnRequest`. A request only: SAML obliges the IdP to nothing and the Response carries no proof, so it is not evidence of fresh authentication.
  - **`spEntityId`** — override the derived SP entityID to adopt one that already exists at the IdP, so an existing SAML app can be migrated without the customer editing their production SSO config. The override flows to the `AuthnRequest`, audience validation, SP metadata, and logout messages through a single resolver, so published metadata stays truthful.
  - **`requireSignedAssertion` / `requireSignedResponse`** — configurable signature posture. Defaults are unchanged (signed assertion required, Response signature not), and now support both defence-in-depth (`requireSignedResponse: true`) and IdPs that sign only the `<Response>`. Turning both off is rejected by the config schema. `WantAssertionsSigned` in SP metadata follows the setting rather than being hardcoded.
  - **`SamlSpProperties.sessionNotOnOrAfter`** — the IdP's `AuthnStatement/@SessionNotOnOrAfter` as Unix ms, when supplied. The library does not act on it; hosts wanting "when their IdP session ends, ours ends" clamp their own session/token TTL to it in `success`.

  **Fixed.** `SamlSpProperties.authnInstant` is now read from the assertion's `AuthnInstant`. It was documented as the assertion's value but silently fell back to the current time, because the underlying library's profile never carried it.

  **Internal.** The ACS parsed the verified assertion three times (Recipient check, replay dedup, and now the `AuthnStatement` read); it parses once and shares the document.

- 20da5d0: SCIM 2.0 group provisioning. Corporate IdPs can now push groups and their membership alongside users, covering the "group push" half of an Okta or Entra provisioning integration.

  **Opt-in as a set.** Implement all six group methods on `ScimDirectory` (`getGroup`, `findGroups`, `createGroup`, `replaceGroup`, `patchGroup`, `deleteGroup`) or none. Omit them and `/scim/v2/Groups` answers `501` — and the discovery documents leave the Group resource type out entirely, so a client is never told a resource works when it does not.

  **Membership keeps the client's intent rather than being resolved.** This is a deliberate departure from how user patches work, and the reason is size: a user's email list is small and bounded, a group's membership is not. Resolving "add one member" against a 20,000-member group would mean reading all 20,000 rows and writing them back on every change. So `patchGroup` receives either `addMembers` / `removeMembers` (incremental — one insert or delete) or `members` (full replace), never both. The library still normalizes the wire shapes, so no SCIM path expression reaches the host: Okta's `{op:"add", path:"members", value:[…]}`, Okta's `members[value eq "u1"]` removal path, and Entra's `{op:"remove", path:"members", value:[…]}` all converge.

  **`excludedAttributes=members` is honoured.** Okta sets it while enumerating groups; `ScimGroupQuery.excludeMembers` lets the host skip loading membership rather than doing a fan-out read per group. Records come back with `members` omitted, not `[]` — an empty array would tell the client the group had been emptied.

  Group filtering supports `displayName`, `externalId` and `id`. Filtering a Group by a user attribute is a `400 invalidFilter` rather than an empty list, which would read as "no such group" — a wrong answer dressed as a valid one.

  Membership operations must be idempotent on the host side: adding an existing member or removing an absent one should succeed quietly, because IdPs retry and a `4xx` there stalls a group push indefinitely.

- bcf9c37: SCIM 2.0 user provisioning. Corporate IdPs (Okta, Entra) can now create, update, and — most importantly — deactivate users in your system automatically, so a customer's directory stays in sync without manual steps. Inbound only: the library receives provisioning and never pushes users anywhere.

  **The library owns the protocol; the host owns the data.** Routing, bearer authentication, RFC 7643 schema validation, PATCH normalization, the error envelope, pagination and the discovery documents live in the library. Every read and write goes through a new `ScimDirectory` port implemented against the host's own tables. No user records are stored in the library — it has no user model, deliberately.

  **Opt-in twice.** Supply `scimDirectory` to `createIdP` (absent ⇒ `/scim/v2/*` answers 501 for the whole deployment), then enable it per tenant with `TenantConfig.scim = { enabled, tokenHash }`, where the token is hashed with the existing `hashClientSecret`.

  **Endpoints:** `/scim/v2/Users` (list with filter + pagination, create) and `/scim/v2/Users/{id}` (get, replace, patch, delete), plus `ServiceProviderConfig`, `ResourceTypes` and `Schemas`. Groups are not implemented and answer 501.

  **What the library absorbs so hosts don't:**

  - **PATCH normalization.** Okta's pathless `{op:"replace", value:{active:false}}`, Entra's `{op:"Replace", path:"active", value:"False"}` (the boolean really does arrive as a string), and targeted paths like `emails[type eq "work"].value` all resolve to one flat delta of fully resolved values. No SCIM path expression and no merge logic reaches the host.
  - **Filtering**, on a deliberately narrow subset — `userName`, `externalId`, `id`, `active`, the complex email path, and two terms joined by `and`. Anything else returns `400 invalidFilter` naming what is supported, rather than a silently wrong result. The parsed filter reaches the port as a typed tree, never a string.
  - **Envelope details** that are easy to get wrong and that certification checks: string `status` in errors, capital-`R` `Resources`, 1-based `startIndex`, `application/scim+json`.

  **Deliberate behaviours worth knowing:**

  - `DELETE` and deactivation stay distinct. A delete is never quietly remapped to `active: false` — that would erase the distinction in an audit trail.
  - `password` in a payload is refused, not silently dropped. Credentials belong to the auth methods, not the directory feed.
  - A malformed PATCH operation on an attribute the library models is an error, never a silent no-op — that is how provisioning drifts undetected. An attribute it does not model is skipped instead, since there is nowhere for it to go and POST/PUT already discard it.
  - A disabled or unconfigured tenant gets `403`, never `404`, so the endpoint cannot be used to probe which tenants exist.
  - A port error other than `conflict` becomes a `500`, which SCIM clients retry — better than reporting success for a write that did not happen.

  **`ScimDirectory` requires read-your-writes consistency**: SCIM clients confirm a create by immediately filtering for it, and a stale read there produces duplicate users. Uniqueness of `userName` is the host's to enforce (return the new `conflict` `AuthError` → `409 uniqueness`); the library cannot enforce a constraint on rows it does not store.

  Also adds a `conflict` variant to `AuthError`, used by hosts to signal that a SCIM write collided with an existing record.

  **Post-review corrections** (found by a branch review before release, all with regression tests): unknown attributes in a PATCH are skipped rather than rejecting the whole request — Okta pushes `title` alongside `active`, so the old behaviour took deactivation down with it, and it was asymmetric with POST/PUT which already ignore them; `/scim/v2/*` no longer distinguishes an unknown tenant from a SCIM-disabled one (the shared tenant middleware previously answered unknown tenants with an OAuth-shaped 400 before the SCIM layer ran, an enumeration oracle); a bare enterprise-extension URN used as a pathless PATCH key now resolves; `add` on a complex attribute merges sub-attributes per RFC 7644 §3.5.2.1 instead of clearing the siblings; filter structural checks ignore quoted literals, so a value containing `(` or the word `or` is no longer rejected; `count=-1` returns zero results per RFC 7644 §3.4.2.4 rather than a full page; creates carry a `Location` header per RFC 7644 §3.1; and a targeted email upsert adopts a lone untyped entry instead of appending a duplicate.

  **Host error contract.** `authError.invalidRequest(…)` from a `ScimDirectory` method now becomes `400 invalidValue` rather than a generic `500`, giving the host a way to signal a _permanent_ rejection. SCIM clients retry `5xx` and give up on `4xx`, so this is the difference between an IdP surfacing a problem to an admin and retrying the same doomed request forever. The motivating case is group membership naming a user the host does not have — an IdP's group push can legitimately reference a member its user push filtered out, or one deleted between operations. `conflict` still maps to `409 uniqueness`; everything else remains a retryable `500`.

## 0.12.0

### Minor Changes

- 1632964: SAML 2.0 Service Provider method family. The library can now consume signed assertions from a corporate IdP (Okta, Entra, Ping, ADFS), so enterprise SAML connections terminate at the IdP and downstream apps keep speaking your OIDC issuer unchanged. It never issues assertions — this is the SP half only.

  **Node-only subpath.** Everything SAML lives at `@_mustachio/openauth/methods/saml-sp`, which carries a `node` export condition. The root entry never re-exports it, so Workers / browser builds stay edge-clean by construction — enforced by `saml-sp-no-thirdparty-leaks.test.ts`. Workers / Durable Object / D1 deployments continue to use the OAuth/OIDC methods.

  **What's new:**

  - **`samlSpFactory`** — a regular `AuthMethodFactory`, so `/authorize` dispatch, the state envelope, the flow record, and the `success` callback all work unchanged. Map key must equal `kind` (`"saml-sp"`); routing is by `kind`, not `type`.
  - **SP-initiated SSO** — outbound `AuthnRequest` (optionally signed via a per-connection `signingKey`) and a full inbound verification gauntlet at the ACS: signature, `Issuer`, `Destination`, explicit `Recipient`, `Audience`, `InResponseTo`, and `NotBefore` / `NotOnOrAfter` with configurable `clockSkewSeconds` (default 60).
  - **IdP-initiated SSO** — opt-in `idpInitiated` block accepts unsolicited Responses (Okta tile, Entra "My Apps") at the same ACS.
  - **Single Logout (SLO)** — SP-initiated logout, inbound front-channel `LogoutRequest`, and the closing front-channel round trip, with an `onLogout` host hook and `challenge.logout`.
  - **Encrypted assertions** behind `allowEncryptedAssertions`, off by default. Requires a `decryptionKey`; SP metadata then advertises a `use="encryption"` `KeyDescriptor`, preserving the advertise-only-what-we-serve invariant.
  - **Anonymous SP metadata endpoint** at `GET /<methodId>/metadata`, served through a general `publicRoutes` mechanism.
  - **`parseSamlIdpMetadata`** — parses IdP metadata XML (Okta and Entra shapes) into config, rejecting malformed input, SP metadata, and metadata with no signing certificate.
  - **Signing-cert hot rotation** — `idp.signingCerts` accepts multiple PEMs with optional `notBefore` / `notAfter` windows, so cert rollover needs no redeploy.
  - **`methodScratch` on `MethodContext`** — new framework primitive for cross-flow method state, backing `InResponseTo` single-use replay protection.

  **Adapter note.** SAML SP requires the `SessionStore` scratch trio (`saveScratch` / `readScratch` / `deleteScratch`). The memory adapter and all four production adapters (Postgres, D1, DynamoDB, Durable Object) implement it; for Postgres and D1 the `openauth_scratch` table is created by the `migrate()` call you already run. A custom `SessionStore` missing the trio fail-fasts at `GET /authorize` with a clear error rather than issuing an AuthnRequest whose id was never cached.

  **Non-breaking.** Additive — a new opt-in subpath plus the `methodScratch` context field and `publicRoutes` mechanism. Existing hosts need no changes; the root entry's public surface is unchanged.

## 0.11.0

### Minor Changes

- 50f4add: OIDC issuance + standards extensions. Brings the library to full OIDC Core RP compatibility and rounds out the OAuth 2.1 surface deferred in 0.10.0. Third-party RPs that use OIDC client libraries (NextAuth, oidc-client-ts, AppAuth, MSAL) now work end-to-end.

  **What's new:**

  - **`id_token` issuance at `/token`** when the `openid` scope is granted.
  - **Pairwise subject identifiers** (OIDC Core §8.1) via per-client `sectorIdentifierUri` / `subject_type: "pairwise"`.
  - **OIDC `claims` request parameter** (OIDC Core §5.5) — RPs can request individual claims at the userinfo / id_token level.
  - **`customScopeClaims`** — host-supplied vendor scope → claim mapping; surface non-standard scopes (e.g. `groups`, `roles`) into id_tokens without forking the library. §5.4 standard mappings always win on key collision; per-client `scopes` allowlist still gates which scopes a client may request.
  - **RP-Initiated Logout** at `/end_session` (OpenID Connect RP-Initiated Logout 1.0).
  - **Pushed Authorization Requests** at `/par` (RFC 9126).
  - **DPoP — sender-constrained access tokens** (RFC 9449), per-client opt-in, with proof replay detection and a dedicated `dpop_replay_detected` audit event.
  - **Dynamic Client Registration** at `/register` (RFC 7591), via host-supplied `registerClient` hook.
  - **Discovery metadata fill-in** — every endpoint, supported algorithm, and feature flag now reflected in `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`.
  - **`/introspect` enrichment** — DPoP `cnf` and OIDC claims surface where applicable.
  - **Audit-log enrichment** — `token_issued` now carries `idTokenIssued` and `dpopBound` flags; new `dpop_replay_detected` event; OIDC + DPoP event surface widened so SIEM dashboards can filter by feature without parsing tokens.

  **Docs:**

  - New top-level [`QUICKSTART.md`](https://github.com/the-human-mustachio/openauth/blob/master/QUICKSTART.md) — 5-minute clone → install → run → verify path, with an LLM-oriented rules-that-bite section.
  - `INTEGRATION.md`, `ARCHITECTURE.md`, and `ports/CONSISTENCY.md` brought up to date with the new endpoints + features.

  **Non-breaking.** All additions are opt-in via scope, client config, or new optional `IdPOptions` fields. Audit event enrichment is additive (new event types + new fields on existing types).

## 0.10.0

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
