---
"@_mustachio/openauth": minor
---

SAML 2.0 Service Provider method family. The library can now consume signed assertions from a corporate IdP (Okta, Entra, Ping, ADFS), so enterprise SAML connections terminate at the IdP and downstream apps keep speaking your OIDC issuer unchanged. It never issues assertions — this is the SP half only.

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
