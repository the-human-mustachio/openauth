# SAML SP — Implementation Plan

> Companion to `idp-rebuild-plan.md`. SAML SP is a new method family that
> plugs into the established `AuthMethodFactory` contract. This plan
> follows the same phase/session structure used in the rebuild plan and
> respects the library boundaries laid out in `ARCHITECTURE.md`.

## TL;DR

Add SAML 2.0 **Service Provider** support as a new method factory
(`samlSpFactory`, `kind: "saml-sp"`) that lives alongside `oauth2Factory`
and `oidcFactory`. The library accepts SAML assertions from upstream
corporate IdPs (Okta, Entra, Ping, ADFS, etc.); it does not issue
assertions. Wrap `@node-saml/node-saml` rather than implement XML-DSig
ourselves. Gate the export Node-only — `xml-crypto` hard-depends on
`node:crypto` and there is no realistic edge path. Phases:
**1** SP-initiated SSO + verification gauntlet (done) → **1.5**
production-adapter enablement (done; deploy gate cleared, one live-IdP
test deferred) → **2** IdP-initiated SSO + SP metadata + explicit
Recipient + signed-AuthnRequest (**done** — Recipient check,
`parseSamlIdpMetadata`, SP-metadata endpoint, IdP-initiated SSO,
signed-AuthnRequest all shipped) → **3** Single Logout +
production polish (**in progress** — architecture signed off:
front-channel SLO both directions via a new *general*
`IdPOptions.onLogout` host hook + `MethodResult.challenge.logout`
field; encrypted assertions behind a flag). Total estimated effort:
~7–9 weeks. See _Status & Resume Point_ for current state.

## Status & Resume Point

> **Maintain this block every working session.** It is the first thing
> to read when resuming with fresh context. The per-phase ✅ markers
> further down are the detailed ledger; this is the summary + the next
> action.

**As of 2026-05-15** — branch `feat/saml-sp`, several commits ahead of
`master` (run `git log --oneline master..feat/saml-sp` for the exact
range — it advances with every doc/commit, so it is intentionally not
frozen here), nothing pushed, nothing merged.

**Done:** SAML Phase 1 (SP-initiated SSO) complete and independently
security-reviewed. End-to-end working: `/authorize` → IdP →
signed-assertion POST → node-saml verification gauntlet → mapped
subject → host `success` callback. Review findings all fixed
(`1509822`). Full suite green; `tsc` strict clean; root entry verified
edge-clean.

**Production blocker — CLEARED (Phase 1.5 done, 2026-05-15):** the
`saveScratch/readScratch/deleteScratch` trio (backs InResponseTo replay
protection) now ships on **all four production adapters** — Postgres,
D1, DynamoDB, Durable Object — in addition to memory. Each is opted
into the `supportsScratch` conformance cases (full set green). Postgres
adds an `openauth_scratch` table; D1 the same (reads pinned to the
primary via `primarySession`); DynamoDB a single-table item with a
native `ttl` attribute + clock-filter on read; Durable Object a keyed
entry. `ports/CONSISTENCY.md` updated with the contract + D1 caveat.
SP-initiated SSO (including replay rejection) verified end-to-end
against `PostgresSessionStore` — not just memory — in
`test/methods/saml-sp/acs-postgres.test.ts`. `INTEGRATION.md` § 9.5
(SAML SP) written: Node-only constraint, scratch-adapter requirement,
per-tenant config shape, derived SP entityID / ACS URL, attribute
cookbook.

**One Phase 1.5 item explicitly deferred (owner decision, 2026-05-15):**
the live Okta/Entra dev-tenant integration test was descoped — it needs
real IdP credentials that are not available in this environment, so it
cannot be executed or meaningfully scaffolded here. Tracked as an open
TODO in the Phase 1.5 acceptance criteria and Definition of Done below;
it does **not** block Phase 2 (the deployability blocker was the scratch
trio, which is resolved).

**Phase 2 — partially done (2026-05-15).** The two framework-change-free
deliverables shipped: (a) the explicit `SubjectConfirmationData/@Recipient`
check (gauntlet item 6) — `checkRecipient` in `acs.ts`, reads the
**signed** assertion via a pinned `@xmldom/xmldom` DOM parse (not the
fragile xml2js walk the plan rejected), denies on mismatch *and* on a
missing Recipient; conformance cases 12 + a `noRecipient` deny case
green. (b) `parseSamlIdpMetadata(xml)` — pure `Result`-returning helper
on the subpath, namespace-prefix agnostic, exported from the barrel and
documented in `INTEGRATION.md` § 9.5. (c) **SP metadata XML endpoint**
— `GET /m/<methodId>/metadata`, anonymous, via the new general
`publicRoutes` framework capability (design pass + sign-off this
session). `buildSpMetadataXml` (pure) + `buildSpMetadata` route;
SPSSODescriptor, HTTP-POST ACS, `AuthnRequestsSigned=false` /
`WantAssertionsSigned=true`, no KeyDescriptor/SLO (standards-valid
omissions), `Cache-Control: s-maxage=300`. An **anti-drift** test
asserts the published entityID/ACS equal what `buildAuthnRequestRedirect`
derives; a **fail-closed** domain test asserts a non-public route is
refused even if the HTTP layer mis-routes.

**Phase 2 — COMPLETE (2026-05-15).** The two remaining framework-invasive
items shipped after their design passes + sign-off:

- ✅ **IdP-initiated SSO (SAML-AD7), bridge V′.** Decided: extend the
  existing `success` variant with optional `unsolicitedBinding`
  (no new `MethodResult` kind → AD3 holds; AD7 carve-out satisfied).
  `AuthMethod.unsolicitedCallback` opt-in; `handleCallback` forks to a
  flowless path when there is **no verifiable state envelope** (a
  correctness fix surfaced in testing: a SAML `RelayState` is not a
  framework envelope, so the fork triggers on "no *verifiable*
  envelope", not just "no state"). No `FlowRecord` is synthesized —
  `saveEncryptedCode` mints from an in-memory `CodePayload`.
  Assertion-ID replay dedup via `methodScratch` (no `InResponseTo` to
  single-use). Open-redirect guard: binding re-validated vs the
  registered client; `RelayState` never a redirect.
- ✅ **Signed-AuthnRequest, option O3.** Decided: the SP signing
  keypair is **per-connection config** (`SamlSpConfig.signingKey =
  {privateKeyPem, certPem}`), decoupled from the OIDC `KeyStore` — the
  IdP pins the cert; rotation is an IdP-coordination event. No
  KeyStore port change, KMS-agnostic. node-saml signs the HTTP-Redirect
  AuthnRequest; SP metadata auto-advertises `AuthnRequestsSigned="true"`
  + a signing `KeyDescriptor` when enabled (kept truthful).

**Phase 3 — IN PROGRESS (architecture signed off 2026-05-18).**
Single Logout (SLO) + production polish. The two forking decisions
were taken with the user:

- **Inbound `LogoutRequest` is host-collaborative.** The library
  cannot unilaterally terminate the right session: a public route has
  no `tokenStore` (`HandlePublicMethodRouteDeps = { sessionStore }`
  only), and the library has **no NameID→OIDC-subject map** — that
  mapping lives in the host's `success(input)` callback (the host owns
  the final `SubjectClaim`). Decision: the library verifies the signed
  `LogoutRequest` (node-saml, SAML-AD1 — no hand-rolled XML-DSig),
  then fires a new *general* `IdPOptions.onLogout` host hook (sibling
  of `success`); the host does its own teardown and may return
  `{ revokeSubject }`, in which case the library runs the existing
  `revokeAllForSubject` (`domain/revoke.ts`) for it. Method handlers
  stay port-free: `/sls` returns `MethodResult.challenge` carrying an
  optional **`logout`** intent (mirrors Phase 2's V′
  `success.unsolicitedBinding` — an optional field on an existing
  variant, not a new `MethodResult` kind; AD3 holds). The privileged
  side-effect runs in the domain public-route pipeline, which gains
  `{ onLogout?, tokenStore, auditLog?, clock }`.
- **Both front-channel directions ship.** IdP-initiated receive
  (`GET/POST /sls`) + SP-initiated send. SP-initiated send is a
  **host-driven method route** (host invokes it from its logout UI),
  **not** an automatic `/end_session` side effect — same rationale as
  above (no session↔method↔`sessionIndex` persistence exists; the
  host owns the identity mapping; a route needs **no new port**).
  `/end_session` stays OIDC-only. Back-channel/SOAP stays out (a
  pre-existing deferred decision).

Encrypted assertions (no fork — mirrors the O3 `signingKey`
precedent): `SamlSpConfig.allowEncryptedAssertions` (default `false`)
+ per-connection `decryptionKey?: { privateKeyPem }` → node-saml
`decryptionPvk`; no port change.

**Progress:**

- ✅ **3b — framework core** (commit `ab246e0`). `IdPOptions.onLogout`
  + `MethodResult.challenge.logout` + public-logout domain pipeline
  ({onLogout?, tokenStore, auditLog?, clock}) + `session_logout`
  `via` discriminant. Riskiest layer (privileged side-effect path)
  tested in `test/domain/method-route-public.test.ts`. The 5th
  general framework change, documented in `ARCHITECTURE.md`.
- ✅ **3c — inbound `LogoutRequest` (IdP-initiated receive).**
  `GET|POST /m/<id>/sls` public route (`sls.ts`), gated public iff
  `idp.sloUrl` is set (mirrors `unsolicitedCallback` ⇐ `idpInitiated`).
  Verifies the signed `LogoutRequest` via node-saml
  (`validateRedirectAsync` / `validatePostRequestAsync` — SAML-AD1,
  both bindings), front-channel replay-dedups the request `@ID` via
  `methodScratch`, emits a signed `LogoutResponse` 302 to `idp.sloUrl`,
  and returns `challenge` + `logout` so 3b's pipeline fires
  `onLogout` → optional `revokeAllForSubject`. SP metadata now
  advertises `SingleLogoutService` (both bindings, same-host anti-drift)
  iff SLO is configured. Tested end-to-end through the real router
  (`sls-http.test.ts`): signed→302+revoke+audit, forged→denied/no
  side effect, replay→rejected, gating, metadata.
- ⏳ **3d** — SP-initiated *send* (host-driven route → `LogoutRequest`
  to `idp.sloUrl`; the `/sls` `SAMLResponse` branch is stubbed,
  validated-and-ack'd, pending 3d enrichment). Then 3e, 3f.

**Recommended next action:** implement increment **3d** (SP-initiated
logout send), completing the front-channel round-trip (conformance
case 16). The live Okta/Entra test remains a tracked follow-up
(deferred, needs creds), not a sequencing blocker.

**Five framework changes SAML drove** (documented in
`ARCHITECTURE.md`), each a *general* capability, not SAML-specific
surface: `MethodContext.methodScratch` (precursor `395ec99`),
`handleCallback` POST-body state recovery (`db45ab6`, also unblocks
OAuth `form_post`), `AuthMethod.publicRoutes` (anonymous flowless
method routes — first user SP metadata),
`AuthMethod.unsolicitedCallback` + `MethodResult.success.unsolicitedBinding`
(flowless inbound authentication — first user IdP-initiated SSO), and
(Phase 3) `IdPOptions.onLogout` + `MethodResult.challenge.logout`
(host-collaborative upstream-logout notification — first user SAML
front-channel SLO; also a foundation for OIDC back-channel logout).

## Goals

- Pass enterprise procurement "SAML 2.0 support" boxes without asterisks.
- Keep the library boundary intact: SAML is just another method, no
  console / admin-API / RBAC bleed-in.
- Reuse the existing `AuthMethodFactory` contract end-to-end — same
  factory shape, same `MethodResult` discriminated union, same
  `MethodConfig.id` per-instance routing, same audit hooks.
- Defeat the known SAML attack classes (XSW1–XSW8, XXE, comment
  truncation, replay, signature exclusion) by leaning on a maintained
  upstream library and verifying its safe-API path at integration time.
- Ship attribute mapping flexible enough to cover the long tail of
  enterprise IdP attribute schemes without forcing a fork per customer.

## Non-Goals

- **SAML IdP role.** The library does not issue SAML assertions to
  downstream apps. Downstream apps speak our OIDC issuer. Revisit only
  if a concrete deployment requires us to act as a SAML hub.
- **Edge runtime support.** SAML is Node-only. Workers / Durable Objects
  / D1 deployments continue to use OAuth/OIDC methods.
- **Encrypted assertions, Holder-of-Key, ECP, Artifact binding.** All
  defensibly omitted on first ship; revisit per-deal.
- **A console for managing SAML connections.** Library owns the
  `MethodStore`-backed persistence shape; host owns the UI for
  uploading IdP metadata, pasting certs, etc.

## Architectural Decisions

These extend the AD-series in `idp-rebuild-plan.md` and `ARCHITECTURE.md`.

### SAML-AD1 — SP only, wraps `@node-saml/node-saml`

Library acts as Service Provider, never Identity Provider. Signature
verification, canonicalization, and XML parsing are delegated to
`@node-saml/node-saml` v5+ (which itself sits on top of `xml-crypto` v6+
with the XSW-safe `getSignedReferences()` path). We do **not**
hand-write XML-DSig.

Rationale: shared maintenance lineage with `xml-crypto` (same `node-saml`
org), commercial sponsorship (Stytch), and a smaller, protocol-only
surface compared to `samlify`. CVE patch coordination matters more here
than feature freshness.

Versions pinned **exactly** (no caret-range):

- `@node-saml/node-saml@5.1.0` — release that patches CVE-2025-54369
  and CVE-2025-54419 (both critical, both affect ≤5.0.1; root cause was
  loading SAML assertions from unsigned original-response content
  rather than from xml-crypto's verified signed-references set).
- `xml-crypto@6.1.2` — well past the 6.0.1 line patching CVE-2025-29774
  (multiple `SignedInfo` bypass) and CVE-2025-29775 (DigestValue
  comment bypass).

This dependency's CVE history has been load-bearing twice in the past
18 months; pin bumps require explicit review and a re-run of the
signature gauntlet fixtures.

### SAML-AD2 — Node-only export

`xml-crypto` requires `node:crypto`; `@xmldom/xmldom` is Node-targeted.
Edge runtimes are out of scope for SAML. The package surfaces SAML
behind a `./methods/saml-sp` subpath export with a `node` condition; the
existing root entry remains edge-clean. CI runs an edge-import test that
imports the public root and fails if any SAML transitive shows up in
the bundle.

### SAML-AD3 — SAML is just a method, not a parallel framework

`samlSpFactory` is an `AuthMethodFactory<P, S, Cfg>` with the same shape
as `oauth2Factory` / `oidcFactory`. No new ports, no new flow lifecycle,
no new `MethodResult` variant. The framework's existing `/<methodId>/*`
dispatch, state envelope, flow record, `success` callback path, and
subject-claim derivation all apply unchanged.

Trade-off accepted: SAML-specific concepts (IdP-initiated SSO,
LogoutRequest, replay state) are wedged into the existing model rather
than getting their own primitives. Spelled out in each session below.

### SAML-AD4 — Per-method-instance trust config, stored via `MethodStore`

A SAML method instance's `MethodConfig.config` carries the IdP entityID,
SSO URL, SLO URL, NameIDFormat preference, attribute mapping, and one or
more PEM-encoded IdP signing certs (with optional `notBefore`/`notAfter`
windows for hot rotation). Persisted via the existing `MethodStore` —
no new port. The host's console is responsible for uploading IdP
metadata XML and parsing it into this shape; the library exposes a
small `parseSamlIdpMetadata(xml)` helper as part of the public API for
hosts that want it.

### SAML-AD5 — SP entityID derived, not configured

Per-instance SP entityID is `<issuerUrl>/<tenantId>/<methodId>` (or a
configurable override). This mirrors the way our OIDC issuer URL is
derived and keeps the entityID stable across deploys for a given
(tenant, methodId) pair. SP metadata is served at
`GET /<methodId>/metadata`.

### SAML-AD6 — Replay state via `SessionStore`, not a new port

Seen assertion IDs ride `SessionStore` with a `saml-replay:<methodId>:`
key prefix and TTL = assertion `NotOnOrAfter` + clock skew. Outstanding
`AuthnRequest` IDs ride `FlowRecord.methodState` (already the standard
spot for per-flow method-private state). No new port; existing
`SessionStore` consistency guarantees (read-your-write, TTL respect) are
documented as sufficient in `ports/CONSISTENCY.md`.

### SAML-AD7 — IdP-initiated SSO requires a synthetic flow + default RP binding

At `POST /acs` with no `InResponseTo`, there is no prior flow record.
The framework's existing `success` path expects a flow (for `client_id`,
`redirect_uri`, scopes, code-challenge). To bridge:

- `SamlSpConfig` exposes optional `idpInitiated: { defaultClientId,
  defaultRedirectUri, defaultScopes }`.
- When ACS sees an unsolicited Response and `idpInitiated` is
  configured, the framework synthesizes a flow at ACS time using those
  defaults plus the verified assertion.
- When `idpInitiated` is absent, ACS rejects unsolicited Responses with
  `invalid_request`. (Conservative default — many deployments don't
  want IdP-initiated.)

This is the one architectural change vs. OAuth/OIDC methods. Spelled
out in Session 2.

## Public API Surface

Everything SAML lives at the **Node-only subpath**
`@_mustachio/openauth/methods/saml-sp`. The root entry
(`@_mustachio/openauth`) never re-exports SAML symbols — this is what
keeps Workers / browsers edge-clean by construction. Re-resolves Open
Question #1 in favour of the consistent answer.

```ts
import {
  samlSpFactory,                    // ✅ shipped
  parseSamlIdpMetadata,             // ✅ shipped (Phase 2 partial, 2026-05-15)
  type SamlSpConfig,                // ✅ shipped
} from "@_mustachio/openauth/methods/saml-sp"
```

`SamlSpConfig` is the validated config shape persisted per method
instance:

```ts
type SamlSpConfig = {
  idp: {
    entityId: string
    ssoUrl: string                       // HTTP-Redirect or HTTP-POST
    sloUrl?: string                      // Single Logout endpoint (Session 3)
    nameIdFormat?: SamlNameIdFormat      // persistent | transient | emailAddress | unspecified
    signingCerts: ReadonlyArray<{
      pem: string
      notBefore?: number
      notAfter?: number
    }>                                   // ≥1; multiple supported for hot rotation
  }
  attributeMapping: SamlAttributeMapping // maps SAML attrs → SubjectClaim shape
  signAuthnRequest?: boolean             // default false; required by some IdPs
  signingKey?: { kid: string }           // KeyStore kid for AuthnRequest signing
  idpInitiated?: {                       // see SAML-AD7
    defaultClientId: string
    defaultRedirectUri: string
    defaultScopes?: string[]
  }
  clockSkewSeconds?: number              // default 60
}
```

No third-party types (`@node-saml/node-saml`, `xml-crypto`) leak through
this surface. Verified by `test/types/public-api-no-thirdparty-leaks.test.ts`
which already gates `jose` / `hono` / `oauth4webapi` /
`@simplewebauthn/server` and gets a new pair of forbidden imports added.

## Type System Additions

Added to `src/types/method.ts` family (no breaking changes):

```ts
type SamlNameIdFormat =
  | "persistent"
  | "transient"
  | "emailAddress"
  | "unspecified"

type SamlAttributeMapping = {
  subject?: SamlAttributeRef             // which attr → providerSubject
  email?: SamlAttributeRef
  emailVerified?: { source: "literal"; value: boolean }
                                         // SAML assertions imply verified
  name?: SamlAttributeRef
  groups?: SamlAttributeRef              // multi-valued
  custom?: Record<string, SamlAttributeRef>
}

type SamlAttributeRef =
  | { source: "nameId" }
  | { source: "attribute"; name: string; format?: string }
```

Method-private state stashed in `FlowRecord.methodState`:

```ts
type SamlSpState = {
  relayState: string                     // framework state envelope, echoed
  issuedAt: number
}
// InResponseTo correlation is NOT here — node-saml's CacheProvider
// (methodScratch-backed) owns it, giving cross-node correlation.
```

Properties emitted on `MethodResult.success` (handed to host's `success`
callback):

```ts
type SamlSpProperties = {
  nameId: { value: string; format: SamlNameIdFormat }
  attributes: Record<string, string | string[]>
  sessionIndex?: string                  // for SLO correlation (Session 3)
  authnInstant: number
  raw: { responseXml: string }           // host's escape hatch
}
```

## Repository Layout

Actual structure as built (Phase 1). `(P2)` / `(P3)` mark files a
later phase will add — they do **not** exist yet.

```
packages/openauth/
├── src/
│   └── methods/
│       └── saml-sp/
│           ├── index.ts                 # Node-only barrel (subpath entry)
│           ├── factory.ts               # samlSpFactory + Zod configSchema
│           ├── method.ts                # buildSamlSpMethod — route table
│           ├── authnrequest.ts          # GET /authorize (unsigned only)
│           ├── acs.ts                   # GET /callback — verification gauntlet
│           ├── saml-instance.ts         # node-saml SAML ctor + binding
│           ├── cache-provider.ts        # methodScratch-backed InResponseTo cache
│           ├── cert-rotation.ts         # selectActiveCertPems (window filter)
│           ├── attributes.ts            # SamlAttributeMapping → properties
│           ├── types.ts                 # exported public types
│           ├── metadata.ts              # (P2) SP metadata XML
│           └── parse-idp-metadata.ts    # (P2) public helper
└── test/
    ├── methods/saml-sp/
    │   ├── cert-rotation.test.ts
    │   ├── config-schema.test.ts
    │   ├── authnrequest.test.ts
    │   ├── acs.test.ts                  # valid + attack matrix + XXE + replay
    │   ├── acs-postgres.test.ts         # (P1.5) SP-init E2E on PostgresSessionStore
    │   └── fixtures/
    │       ├── build-response.ts        # signSamlPost-based fixture builder
    │       ├── idp-{cert,key}.pem       # matched test IdP keypair
    │       └── attacker-{cert,key}.pem  # wrong-key fixture
    └── types/
        ├── saml-sp-no-thirdparty-leaks.test.ts   # compile-time leak guard
        └── saml-sp-edge-clean-root.test.ts       # source-level isolation scan
```

There is **no** `replay.ts` (replay is node-saml's single-use
`InResponseTo`, not a bespoke guard) and **no**
`test/conformance/saml-sp.test.ts` — the gauntlet is exercised
end-to-end inside `test/methods/saml-sp/acs.test.ts` (see
_Security Gauntlet_). The original plan listed those; they were
superseded during implementation.

This mirrors the existing pattern: methods are flat under
`src/methods/` for trivial wrappers and gain their own subdirectory
when internal structure justifies it (cf. `methods/providers/`).

## Method Plumbing

`samlSpFactory.build` returns an `AuthMethod<SamlSpProperties, SamlSpState>`.

**Routing reality (corrected after implementation).** The framework
does not mount arbitrary method sub-paths for the upstream callback.
It exposes one universal callback, `/cb/<methodId>` (both GET and
POST), and `handleCallback` always dispatches the **`"GET /callback"`**
route key regardless of HTTP verb. `ctx.dispatch.callbackUrl` is that
`/cb/<methodId>` URL. So SAML does **not** get bespoke `/acs`,
`/metadata`, `/sls` sub-paths — the ACS lives at the `"GET /callback"`
route key, and metadata/SLS will be served via the credential-style
`/m/<methodId>/*` mount (`app.all("/m/*")`) in later sessions.

| Route key          | Trigger                                       | Behaviour                                                                                                                                  | Status |
| ------------------ | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| `GET /authorize`   | Framework dispatch from `/authorize`          | Build AuthnRequest (HTTP-Redirect binding) via node-saml, save `SamlSpState` to `methodState`, `MethodResult.challenge` 302 to IdP SSO.    | **Done** |
| `GET /callback`    | IdP HTTP-POST to `/cb/<methodId>` (universal) | Verify Response — the full gauntlet via node-saml. Returns `success` / `denied` / `error`.                                                 | **Done** |

Later sessions add, via the `/m/<methodId>/*` mount:

| Path                          | Trigger                | Behaviour                                                                 |
| ----------------------------- | ---------------------- | ------------------------------------------------------------------------- |
| `/m/<methodId>/metadata`      | Anonymous, public      | SP metadata XML. `CachePolicy.sMaxAge = 300`. (Session 2)                 |
| `/m/<methodId>/sls`           | IdP front-channel SLO  | Verify LogoutRequest, revoke session, redirect LogoutResponse. (Session 3)|

IdP-initiated SSO cannot ride `/cb/<methodId>` — `handleCallback`
verifies the state envelope and consumes a pre-existing flow before
dispatch, neither of which exists for an unsolicited Response. It
therefore needs the synthetic-flow path (SAML-AD7) wired through a
different entry; tracked for Session 2.

All routes obey the existing constraint (`src/types/method.ts:9`):
methods do **not** import from `src/http/`, `src/adapters/`, or
`src/ports/`. node-saml is imported only inside `src/methods/saml-sp/`
and only reached at request time inside the route handlers, so the
factory/type surface stays cheap and the edge-clean guards stay green.

**Resolved decisions from this increment:**

- **`SamlSpState` = `{ relayState, issuedAt, spEntityId, acsUrl }`.**
  `authnRequestId` was dropped — `InResponseTo` correlation is handled
  by node-saml's `CacheProvider` (`cache-provider.ts`,
  `methodScratch`-backed, cross-node for free). `spEntityId` + `acsUrl`
  were *added*: they are derived at AuthnRequest time (where
  `ctx.dispatch` is available) and read back at the ACS (where
  `ctx.dispatch` is `null`) so the assertion's AudienceRestriction is
  validated against the exact value the IdP saw in the request.
- **Second framework change: POST-body state recovery.** SP-initiated
  SAML uses the HTTP-POST binding — the state envelope arrives as
  `RelayState` in the form body, but `handleCallback` only read
  `?state=` from the query. Added `extractCallbackState(req)`: query
  first, then a **cloned** body read (`state` for OAuth `form_post`,
  `RelayState` for SAML) when the query param is absent. This is a
  *general* POST-callback fix (also unblocks true OAuth `form_post`),
  not SAML-specific; the router already declared intent to support
  `POST /cb/*`. The clone keeps the body intact for the ACS handler.
  Documented in `ARCHITECTURE.md`. So SAML drove **two** framework
  changes total: `methodScratch` (precursor) and this.
- **`methodScratch` shipped as a precursor**, not in-session. The
  `MethodContext.methodScratch` shim (`{ put, get, delete }`, scoped
  `scratch:<tenantId>:<methodId>:`, `SessionStore`-backed) landed
  ahead of this increment. Documented in `ARCHITECTURE.md`.
- **`wantAuthnResponseSigned: false`, `wantAssertionsSigned: true`.**
  Requiring the *assertion* signed is mandatory (identity, Conditions
  and AudienceRestriction all live in the signed bytes). Also
  requiring the outer `<Response>` signed is stricter than the
  Okta/Entra default and would reject the majority of real IdPs, so it
  is not required. Encrypted-assertion / signed-response options are a
  later session.
- **`signAuthnRequest` deferred within Phase 1.** Signing the outbound
  AuthnRequest needs a `KeyStore`-resolved private key, and
  `MethodContext` does not (yet) expose `KeyStore`. The handler
  rejects `signAuthnRequest: true` with a clear error rather than
  silently emitting an unsigned request. Unsigned AuthnRequests are
  accepted by the large majority of IdPs; signed-request support is a
  later Phase 1 increment that also decides how methods reach signing
  keys.

## Security Gauntlet — what enforces each item (post-implementation)

Per SAML-AD1 we do **not** reimplement XML-DSig. The cryptographic
gauntlet is `@node-saml/node-saml@5.1.0`'s `validatePostResponseAsync`
(the CVE-2025-54369/54419-hardened path), driven by our strict
`buildSamlInstance` config. Every gauntlet item below is exercised
end-to-end through `dispatchMethod` in `test/methods/saml-sp/acs.test.ts`.

| # | Item | Enforced by | Test |
| - | ---- | ----------- | ---- |
| 1 | XML well-formedness / no entity expansion (XXE) | `@xmldom/xmldom` (no external-entity resolution) | `XXE: external entity is never expanded into the subject` |
| 2 | Signature present | node-saml `wantAssertionsSigned: true` | `attack: unsigned assertion` |
| 3 | Signature verifies vs configured cert (within rotation window) | node-saml + `selectActiveCertPems` | `attack: signed with wrong key` |
| 4 | Issuer match | node-saml `idpIssuer` | covered by valid + audience cases |
| 5 | AudienceRestriction = SP entityID | node-saml `audience` | `attack: audience mismatch` |
| 6 | SubjectConfirmationData/@Recipient = ACS URL | **NOT enforced by node-saml — deferred** (see below) | — |
| 7 | InResponseTo single-use | node-saml `validateInResponseTo: always` + `methodScratch` cache | `replay rejected` |
| 8 | Conditions/SubjectConfirmation timestamps within skew | node-saml `acceptedClockSkewMs` | `attack: expired conditions` |
| 9 | Replay | for SP-init, subsumed by item 7 (request id is single-use); explicit assertion-ID dedup lands with IdP-init (Session 2) | `replay rejected` |
| 10 | Signed-references-only extraction (XSW) | node-saml `getVerifiedXml` → `getSignedReferences()`; exactly-one-ID + signature-is-parent checks | `attack: signature-wrapping (XSW)` |
| 11 | NameID comment safety (CVE-2018-0489 class) | inherited from node-saml's verified-content read | covered by XSW + valid cases |

**Item 6 (Recipient) — deferred, documented.** node-saml validates
Issuer, AudienceRestriction, Conditions/SubjectConfirmation timestamps
and InResponseTo, but does **not** validate
`SubjectConfirmationData/@Recipient`. Audience (= our SP entityID,
enforced) plus single-use InResponseTo already bind the assertion to
this SP and this request, so Recipient is defense-in-depth rather than
the primary binding. An explicit Recipient check (reading the verified
assertion) is tracked as a Phase 1 follow-up and lands with the
IdP-initiated work, where assertion-level parsing is needed anyway.
Shipping a fragile xml2js-shape extractor now would be worse than the
documented gap.

## Phase Plan

### SAML Phase 1 — SP-initiated SSO + verification gauntlet

**Goal:** Pass a real Okta or Entra SAML connection end-to-end for an
SP-initiated flow, with the full signature gauntlet locked down.

**Deliverables (✅ = shipped):**

- ✅ `samlSpFactory` with `kind: "saml-sp"`, full `SamlSpConfig` Zod
  schema (Standard Schema v1 conformant), incl. the
  `signAuthnRequest ⇒ signingKey` cross-field rule.
- ✅ `GET /authorize` route — builds AuthnRequest (HTTP-Redirect
  binding) via node-saml, 302 to IdP SSO, RelayState = state
  envelope. Unsigned only; `signAuthnRequest: true` rejected with a
  clear error (KeyStore-in-MethodContext is a later increment).
- ✅ `"GET /callback"` ACS route (`acs.ts`) — gauntlet via node-saml
  `validatePostResponseAsync`; failures → `denied`, infra faults →
  `error`, success → mapped `SamlSpProperties`. SP-init only;
  Recipient (item 6) deferred (documented). Plus the general
  `handleCallback` POST-body state-recovery fix.
- ✅ Attribute mapping engine (`attributes.ts`,
  `SamlAttributeMapping` → `SamlSpProperties`) — pure, no node-saml
  type leak; `mapProfile` returns a `denied` reason on empty subject.
- ✅ `methodScratch` addition to `MethodContext` — shipped as a
  precursor PR. Memory only at Phase 1; the four production adapters
  landed in **Phase 1.5 (done, 2026-05-15)** — scratch now works on
  every bundled adapter.
- ✅ Replay — SP-init covered by node-saml single-use InResponseTo
  (`validateInResponseTo: always` + `methodScratch` cache). Explicit
  assertion-ID dedup deferred to IdP-init (Session 2).
- ✅ **node-saml cert-rotation shim** — `selectActiveCertPems`
  (`cert-rotation.ts`), a pure window filter feeding node-saml's
  `idpCert`. Tests: single, overlap, expired-only, inclusive
  `notBefore` / exclusive `notAfter`, order preservation.
- ✅ Node-only subpath export (`./methods/saml-sp`) + the source-level
  edge-clean scan + the compile-time leak guard.
- Test suite: ✅ `cert-rotation.test.ts`, ✅ `config-schema.test.ts`,
  ✅ `authnrequest.test.ts`, ✅ `acs.test.ts` (valid + 5-attack matrix
  + XXE-no-disclosure + replay, end-to-end through `dispatchMethod`
  with a real node-saml instance and `signSamlPost`-signed fixtures).
- ✅ Leak guard forbids `@node-saml/*` / `xml-crypto` from the root
  (`saml-sp-no-thirdparty-leaks.test.ts` +
  `saml-sp-edge-clean-root.test.ts`).
- Live Okta/Entra integration test + `INTEGRATION.md` § SAML SP —
  **moved to Phase 1.5** (it must run against a production adapter,
  which doesn't exist until 1.5). Not a Phase 1 deliverable.

**Acceptance criteria (status reconciled):**

- ✅ Gauntlet items each have ≥1 end-to-end test — **except item 6
  (Recipient)**, which node-saml does not enforce and is explicitly
  deferred (see _Security Gauntlet_). Items 4/9/11 are covered
  transitively (valid + XSW + audience cases), not by a dedicated
  failing fixture; the others have one.
- ⏳ **Deferred:** Okta/Entra dev-tenant live integration. Verified
  against `signSamlPost`-signed fixtures only; a real-IdP test is the
  next step after the production-adapter scratch work (see _Status &
  Resume Point_).
- ✅ `bunx tsc --noEmit -p tsconfig.test.json` exits 0 under strict.
- ✅ Edge-clean guards pass (no SAML transitive reachable from the
  root entry).

Net: the gauntlet bar is met for what node-saml enforces; the two
gaps (Recipient, live-IdP test) are tracked, not silent.

**Risks:**

- `@node-saml/node-saml` API surface change between versions. **Mitigation:**
  pin to exact patch version, add a smoke test that fails if a major
  bump silently changes the signed-references API contract.
- Attribute mapping spec drift across IdPs. **Mitigation:** ship Okta
  + Entra fixtures in tests; document the "if it isn't here, add a
  custom mapper" escape hatch.

**Estimated effort:** 3 weeks.

---

### SAML Phase 1.5 — Production adapter enablement (BLOCKS Phase 2)

**Goal:** Make SAML actually deployable. After Phase 1, SP-initiated
SSO works correctly but only on the in-memory `SessionStore` (single-
process dev). This is the single hard blocker between "demoable" and
"shippable". It is small, mechanical, and must land before Phase 2 —
building more SAML surface on a non-deployable base is wasted motion.

**Deliverables (✅ = shipped 2026-05-15):**

- ✅ Implemented the `saveScratch` / `readScratch` / `deleteScratch`
  trio on every production `SessionStore` adapter: **Postgres, D1,
  DynamoDB, Durable Object**. Strong-consistency, TTL-respecting,
  opaque key/value. Semantics are **upsert / TTL-filtered read /
  idempotent delete** — there is no atomic delete-on-read, so this
  tracks the `createSession`/`readSession`/`revokeSession` shape, not
  `consumeFlow`. Per-adapter:
  - ✅ Postgres: `openauth_scratch (scratch_key text PK, value text,
    expires_at bigint)`; `INSERT … ON CONFLICT DO UPDATE`; lazy GC on
    expired read.
  - ✅ DynamoDB: single-table item `pk="scratch"` + native `ttl`
    attribute (best-effort eviction) **and** a clock filter on read
    for correctness.
  - ✅ D1: same SQL shape as Postgres; all three ops pinned to the
    primary via `primarySession` (scratch is read-after-write
    sensitive for InResponseTo — see `ports/CONSISTENCY.md` D1
    caveat).
  - ✅ Durable Object: keyed entry `scratch:<key>` → `{value,
    expiresAt}`; lazy-delete on expired read. No transaction needed
    (no read-modify-write; the DO serializes writes).
- **Plan-vs-reality correction:** the deliverable text said to "mirror
  the existing optional-method pattern (`savePar`/`consumePar`)" and
  "reuse the PAR table pattern." There is **no production PAR
  precedent** — `savePar`/`consumePar` exist only on the memory
  adapter; no `openauth_par` table exists. Scratch was instead modeled
  on the production flow-record / session storage patterns that do
  exist, plus the memory scratch impl for semantics. No scope change.
- ✅ Opted each adapter into the conformance suite
  (`describeSessionStore({ …, supportsScratch: true })`); the shared
  suite's scratch cases (round-trip, overwrite, unknown→`unknown_state`,
  expiry, idempotent delete, ttl≤0, key isolation) pass for all four.
- ✅ `ports/CONSISTENCY.md`: scratch contract row confirmed; D1
  read-after-write caveat added; graceful-degradation note updated to
  reflect production-adapter coverage.
- ⏳ **Deferred (owner decision, 2026-05-15):** live integration test
  against Okta **and** Entra dev tenants. Requires real IdP
  credentials not available in this environment; descoped rather than
  scaffolded as dead code. Tracked here and in the DoD. Does not block
  Phase 2.
- ✅ `INTEGRATION.md` § 9.5 (SAML SP): Node-only constraint,
  scratch-adapter requirement, per-tenant config shape, derived SP
  entityID / ACS URL, manual IdP configuration, attribute-mapping
  cookbook. (Live-IdP harness intentionally omitted per the deferral
  above.)

**Acceptance criteria (status reconciled):**

- ✅ All four production adapters pass the `supportsScratch`
  conformance cases.
- ✅ SP-initiated SSO completes end-to-end on Postgres (not just
  memory) — `test/methods/saml-sp/acs-postgres.test.ts` (valid →
  success; replay → rejected via Postgres-backed InResponseTo scratch).
- ⏳ **Deferred:** at least one real-IdP (Okta or Entra) login
  verified end-to-end. Open TODO — needs dev-tenant creds; see the
  deferral note above.

**Risks:**

- D1 read-replication lag could make a just-saved InResponseTo invisible
  at the ACS → spurious auth failures. **Mitigation:** scratch reads use
  the same primary-pinned / bookmarked path as flow records; covered by
  the existing D1 consistency certification (`ports/CONSISTENCY.md`).

**Estimated effort:** ~1 week (mechanical; the conformance suite
already exists, so it is mostly per-adapter SQL/DO plumbing + the
live-IdP test harness). **Status: done 2026-05-15** except the
deferred live-IdP harness (see Deliverables / Status & Resume Point).

---

### SAML Phase 2 — IdP-initiated SSO + SP metadata + explicit Recipient

**Goal:** Cover the Okta-default IdP-initiated flow, publish SP
metadata enterprise IdPs can import, and close the deferred
Recipient-binding gap.

> Cert rotation is **already shipped in Phase 1** (`cert-rotation.ts`,
> `selectActiveCertPems`, with overlap-window tests) — it is *not* a
> Phase 2 deliverable. The title kept "+ cert rotation" in an earlier
> draft; corrected here.

**Deliverables (✅ = shipped 2026-05-15, partial Phase 2):**

- ✅ **Explicit `SubjectConfirmationData/@Recipient` check** (gauntlet
  item 6) — `checkRecipient` in `acs.ts`. Reads the **signed**
  assertion (`profile.getAssertionXml()`) via a pinned
  `@xmldom/xmldom@0.8.13` DOM parse, namespace-agnostic
  (`getElementsByTagNameNS("*", …)`), compares every
  `SubjectConfirmationData/@Recipient` to the exact ACS URL committed
  at AuthnRequest time. Denies on mismatch **and** on a missing
  Recipient (Web Browser SSO bearer profile requires it); `error`
  (fail-loud) if node-saml ever stops exposing `getAssertionXml`.
  Recon found this does **not** need the IdP-init xml2js work the plan
  assumed it was coupled to — a deterministic DOM parse of verified
  bytes is the non-fragile path. Tests: `badRecipient` + new
  `noRecipient` knobs in the `acs.test.ts` attack matrix.
- ✅ `parseSamlIdpMetadata(xml)` public helper —
  `src/methods/saml-sp/parse-idp-metadata.ts`, pure,
  `Result`-returning, no node-saml import, namespace-prefix agnostic.
  Parses into the `SamlIdpConfig` shape (entityId, ssoUrl, sloUrl?,
  nameIdFormat?, signingCerts[{pem}]); PEM-normalises X509 bodies;
  rejects SP metadata / missing IDPSSODescriptor / cert / entityID.
  Exported from the subpath barrel; `INTEGRATION.md` § 9.5 updated.
  Tests: `parse-idp-metadata.test.ts` (Okta + Entra shapes + 5
  rejection cases).
- ✅ **`idpInitiated` SSO (SAML-AD7), bridge V′** (2026-05-15). No
  synthetic `FlowRecord` — the recon found `saveEncryptedCode` works
  off an in-memory `CodePayload`, so the framework mints directly from
  `MethodResult.success.unsolicitedBinding` (a minimal optional field,
  not a new variant — AD3 holds, AD7 carve-out met).
  `AuthMethod.unsolicitedCallback` opt-in; `handleCallback` forks when
  there is **no verifiable** state envelope (testing surfaced that a
  SAML `RelayState` is not a framework envelope — the fork keys on
  "no verifiable envelope", not "no state"). Assertion-ID replay dedup
  via `methodScratch`; open-redirect guard re-validates the binding vs
  the registered client; `RelayState` never a redirect. Tests:
  `idp-initiated.test.ts` (success→302+code, replay→denied, not-opted
  →invalid_request unchanged, hostile RelayState).
- ✅ **SP metadata XML endpoint** (2026-05-15). Served anonymously at
  `GET /m/<methodId>/metadata` via the new general `AuthMethod.publicRoutes`
  opt-in (the original plan's "`/m/*` mount" assumption was wrong —
  `/m/*` is flow-cookie-gated; the design pass replaced it with a
  fail-closed, reusable public-route capability — see `ARCHITECTURE.md`
  § `publicRoutes`). `metadata.ts`: pure `buildSpMetadataXml` +
  `buildSpMetadata` route; `domain/method-route.ts`:
  `handlePublicMethodRoute` with an independent membership re-check;
  `http/handlers/method-route.ts`: additive public fast-path leaving
  the gated path byte-identical. `cacheControlFor` lifted to
  `http/cookies.ts` as `cacheControlHeader` (shared, no third copy).
  Anti-drift + fail-closed tests green. (`parseSamlIdpMetadata` — the
  *inbound* side — was already done; this is the *outbound* side.)
- ✅ **Signed-AuthnRequest, option O3** (2026-05-15). SP signing
  keypair is per-connection config (`signingKey = {privateKeyPem,
  certPem}`), decoupled from the OIDC `KeyStore` — the IdP pins the
  cert; rotation is an IdP-coordination event. No KeyStore port
  change, KMS-agnostic. node-saml signs the HTTP-Redirect
  AuthnRequest; SP metadata auto-advertises `AuthnRequestsSigned="true"`
  + signing `KeyDescriptor` when enabled (truthful). Schema enforces
  `signAuthnRequest ⇒ signingKey`. Tests: `authnrequest.test.ts`
  (signed redirect carries SigAlg+Signature; unsigned has neither),
  `config-schema.test.ts`, `metadata.test.ts` (signing advertised).
- ✅ Test extensions landed: `idp-initiated.test.ts`,
  `metadata.test.ts` (incl. signed-metadata + DOM structure).
  `recipient.test.ts` superseded (coverage in `acs.test.ts`);
  metadata-parse coverage in `parse-idp-metadata.test.ts`.
- ✅ `INTEGRATION.md` § 9.5 extended with IdP-initiated + signed-
  AuthnRequest configuration (incl. the SP-key at-rest note).

**Acceptance criteria:**

- Okta IdP-initiated tile → land in host app, fully authenticated.
- Entra dev tenant imports our metadata XML without manual edits.
- `RelayState` is treated as a host-supplied opaque token in
  IdP-initiated flows; the framework refuses to interpret it as a
  redirect URL (open-redirect guard).

**Risks:**

- IdP-initiated open-redirect class of bugs. **Mitigation:** explicit
  test that arbitrary `RelayState` values cannot redirect outside the
  configured `defaultRedirectUri` origin; documented in
  `ARCHITECTURE.md` § Response sanitization.

**Estimated effort:** 1.5–2 weeks.

---

### SAML Phase 3 — Single Logout (SLO) + production polish

**Goal:** Close the last common procurement checkbox and harden for
production rollout.

**Architecture (signed off 2026-05-18 — see _Status & Resume Point_
for the decision record and rationale):** host-collaborative SLO via
the general `IdPOptions.onLogout` hook + `MethodResult.challenge.logout`
field; both front-channel directions; SP-initiated send is a
host-driven method route, not an `/end_session` side effect;
`/end_session` stays OIDC-only.

**Deliverables:**

- **3b — Framework core.** `IdPOptions.onLogout` (general host hook,
  sibling of `success`; may return `{ revokeSubject }` →
  `revokeAllForSubject`). `MethodResult.challenge.logout?` optional
  field (mirrors V′; AD3 holds). Public-route domain pipeline gains
  `{ onLogout?, tokenStore, auditLog?, clock }`; a logout-carrying
  challenge fires `onLogout` → optional revoke → returns the
  `LogoutResponse` redirect. `ARCHITECTURE.md` section.
- **3c — Inbound `LogoutRequest` (IdP-initiated receive).**
  `GET/POST /sls` (public route) verifies the signed `LogoutRequest`
  via node-saml (`validateRedirectAsync` / `validatePostRequestAsync`
  — SAML-AD1, no hand-rolled XML-DSig), builds the signed
  `LogoutResponse`, returns `challenge` + `logout` intent.
- **3d — SP-initiated send.** Host-driven method route builds a
  signed `LogoutRequest` redirect to `idp.sloUrl`; the returned
  `LogoutResponse` is validated at `/sls`. Completes the
  front-channel round-trip (conformance case 16).
- **3e — Encrypted-assertion support behind a feature flag**
  (`SamlSpConfig.allowEncryptedAssertions: boolean`, default `false`)
  + per-connection `decryptionKey?: { privateKeyPem }` (mirrors the
  O3 `signingKey` precedent — decoupled from the OIDC `KeyStore`, no
  port change). Wired to `@node-saml/node-saml`'s `decryptionPvk`
  (its `xml-encryption` integration).
- Audit-log catalog additions: `saml_authn_request_built`,
  `saml_response_verified`, `saml_response_rejected{reason}`,
  `saml_replay_detected`, `saml_logout_request_received`,
  `saml_logout_completed`.
- Performance benchmark vs. an OIDC connection: assert no >2x latency
  delta at p95 (canonicalization is heavier than JWT verify but
  shouldn't be catastrophic).
- Security review checklist (internal): walk the OASIS SAML 2.0
  Security Considerations doc + the OWASP SAML cheatsheet against our
  implementation. Document gaps.

**Acceptance criteria:**

- Okta front-channel SLO round-trips successfully.
- Encrypted assertion from a configured Okta connection round-trips
  when feature flag is on, rejected with `unsupported_binding` when
  off.
- All audit events fire in conformance tests.

**Risks:**

- Back-channel SLO (SOAP) is a real interop ask in regulated industries
  but a much larger surface. **Decision deferred:** ship front-channel
  only; add a `Risks & Mitigations` entry noting back-channel SLO is
  not supported.

**Estimated effort:** 1.5–2 weeks.

## Sequencing & Parallelism

- SAML Phase 1 is **blocked by** the `methodScratch` framework
  addition. That work is small (≤1 day) and lands as a precursor PR
  ahead of Phase 1's main body.
- SAML Phase 1 → **1.5** → 2 → 3 are strictly sequential. Phase 1.5
  (production adapter enablement) **blocks** Phase 2 — there is no
  value in adding IdP-initiated / metadata surface on a base that
  only runs in single-process memory. Phase 1.5 is mechanical and the
  conformance suite for it already exists.
- SAML work is **parallelizable with** remaining IdP Phase 8 sessions
  (DPoP, PAR, mTLS, DCR, rate limiting, logging/tracing) because they
  touch mostly disjoint code paths. As built, SAML touched
  `src/methods/saml-sp/` (new), `src/types/method.ts` +
  `src/domain/method-dispatch.ts` + `src/ports/session-store.ts` +
  the memory adapter (the `methodScratch` precursor), and
  `src/domain/callback.ts` (the general POST-body state recovery). It
  did **not** modify `src/http/router.ts` — the `/cb/*` and `/m/*`
  mounts already existed. Phase 8 sessions touch `src/domain/`
  token/grant code; the one overlap point is `src/domain/callback.ts`,
  already landed.
- SCIM is **deferred** until SAML Phase 1 ships (per current
  prioritization discussion). SCIM and SAML are commercially adjacent
  but technically independent; once SAML Phase 1 unblocks the
  "supports SAML" RFP claim, SCIM becomes the next-largest enterprise
  unlock.

## Cross-cutting Decisions Captured

- **Library choice locked to `@node-saml/node-saml`** (not `samlify`).
  Rationale: shared maintenance with `xml-crypto`, commercial
  sponsorship, narrower API surface. Documented above as SAML-AD1.
- **No new ports.** Replay state rides `SessionStore` via the new
  `methodScratch` shim; certs ride `MethodConfig`. The only framework
  surface change is `methodScratch` on `MethodContext` (Session 1).
- **Subject-claim derivation reuses the existing
  `IdPOptions.success(input)` contract.** SAML success hands
  `providerSubject` (post-mapping NameID or chosen attribute) and
  `properties: SamlSpProperties` to the host callback; the host owns
  the final `SubjectClaim`. No SAML-specific subject shape.
- **`samlSpFactory.kind === "saml-sp"`** (not just `"saml"`) to leave
  semantic room if the library ever does add a SAML IdP role later.
  Re-aliasing later breaks `MethodConfig.kind` rows in stored configs,
  so pick the future-safe name now.
- **AuthnRequest signing is per-instance opt-in.** Many IdPs don't
  require it. When enabled, signing key is supplied via a `KeyStore`
  `kid` reference, matching how our OIDC issuer signs `id_token`s.

## Conformance Scope

**Implementation note:** unlike OAuth/OIDC (which use
`test/conformance/*.test.ts`), the SAML gauntlet lives in
`test/methods/saml-sp/acs.test.ts` + `cert-rotation.test.ts` +
`config-schema.test.ts`, driven end-to-end through `dispatchMethod`.
There is no `test/conformance/saml-sp.test.ts`; the earlier plan
assumed one. The matrix below is the **cross-phase target**, not a
single file. Result classification is `success` / `denied` (reason =
node-saml's message, free-text — **not** typed reason codes) / `error`.

| # | Case                                              | Phase | Status |
| - | ------------------------------------------------- | ----- | ------ |
| 1 | SP-initiated SSO end-to-end (fixture)             | 1     | ✅ (`signSamlPost` fixture; real Okta/Entra deferred) |
| 2 | Valid → mapped `SamlSpProperties`                 | 1     | ✅ |
| 3 | Unsigned assertion → not `success`                | 1     | ✅ |
| 4 | Wrong-cert signature → not `success`              | 1     | ✅ |
| 5 | Audience mismatch → not `success`                 | 1     | ✅ |
| 6 | Stale `NotOnOrAfter` → not `success`              | 1     | ✅ |
| 7 | XSW wrapping → not `success`                      | 1     | ✅ |
| 8 | XXE → external entity never expanded into subject | 1     | ✅ |
| 9 | Replay (same Response twice) → 2nd not `success`  | 1     | ✅ |
| 10| `signAuthnRequest:true` → **signed** redirect (O3; was "rejected" pre-Phase-2) | 2 | ✅ (SigAlg+Signature; unsigned has neither) |
| 11| No cert in validity window → `error`              | 1     | ✅ |
| 12| `Recipient` mismatch → not `success`              | 2     | ✅ (`checkRecipient`; + `noRecipient` deny case) |
| 13| IdP-initiated success with `defaultClientId`      | 2     | ✅ (`idp-initiated.test.ts` — 302+code) |
| 14| IdP-initiated with hostile `RelayState`           | 2     | ✅ (never a redirect; replay deduped) |
| 15| SP metadata XML matches IdP-importer expectations | 2     | ✅ (`metadata.test.ts`; anti-drift vs AuthnRequest) |
| 16| Front-channel SLO round-trip                      | 3     | 🟡 receive half ✅ (`sls-http.test.ts`: signed→302+revoke+audit, forged→denied, replay→rejected); SP-initiated send ⏳ 3d |
| 17| Encrypted assertion off → rejected                | 3     | ⏳ |
| 18| Encrypted assertion on → accepted                 | 3     | ⏳ |

OASIS interop suite integration is **not in scope** (matches existing
posture per `idp-rebuild-plan.md` § Conformance Scope — hand-built
matrix only).

## Open Questions

1. ~~**Should `parseSamlIdpMetadata` be exposed from the Node-only
   subpath or the root entry?**~~ **Resolved** — subpath only. All SAML
   symbols live at `@_mustachio/openauth/methods/saml-sp`; the root
   entry never re-exports any of them. Enforced by
   `test/types/saml-sp-no-thirdparty-leaks.test.ts` (compile-time root
   probes) and `test/types/saml-sp-edge-clean-root.test.ts` (source-
   level scan of `src/` for forbidden imports).
2. **How does the host's console upload IdP metadata?** The library
   exposes `parseSamlIdpMetadata`; the wire-up is host responsibility.
   `INTEGRATION.md` § SAML SP needs a worked example. Coordinate with
   whoever owns the host console before Phase 2 lands so the host UI
   can ship in the same release.
3. ~~**Do we want a `SamlEventEmitter` port for SLO push** (so the
   host can fan out logout to other systems)?~~ **Resolved
   (2026-05-18)** — no new port. The general `IdPOptions.onLogout`
   host hook is the fan-out point: the host receives the verified
   logout intent and drives whatever downstream notification it
   needs. Consistent with the locked "no new ports" cross-cutting
   decision and the host-collaborative boundary.
4. **AuthnContext class refs.** Some IdPs require us to assert
   `AuthnContextClassRef` (e.g., MFA-required). Worth a config option?
   Defer to Phase 3 polish unless raised in customer feedback before
   then.

## Risks & Mitigations

| Risk                                                                 | Mitigation                                                                                                |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `@node-saml/node-saml` ships an XSW-class CVE                        | Pin exact patch version (no caret-range); subscribe to GitHub Security Advisories feed for `node-saml/*`; have a rollback strategy. Recent precedents: CVE-2025-54369 / 54419 (node-saml ≤5.0.1), CVE-2025-29774 / 29775 (xml-crypto ≤6.0.0). The current pins (`node-saml@5.1.0` + `xml-crypto@6.1.2`) post-date all four. |
| Customer brings a SAML IdP we haven't tested (Ping, ADFS, Shibboleth)| Fixture corpus expands per customer; gauntlet items are protocol-spec-based, not IdP-specific.            |
| Attribute mapping fails for a non-standard schema                    | Custom mapping escape hatch via `SamlAttributeMapping.custom`; documented examples in `INTEGRATION.md`.    |
| Node-only export confuses Workers users                              | Build-time guard + clear error message at import time on edge runtimes; documented in `INTEGRATION.md`.   |
| IdP-initiated SSO becomes an open-redirect vector                    | Explicit test (case 13); `RelayState` is opaque to the framework in IdP-initiated mode.                   |
| `methodScratch` becomes a backdoor for other methods                 | Document scope tightly: only for cross-flow per-method state; not a general-purpose key-value store.      |

## Definition of Done (overall)

- All phases shipped — **1, 1.5, 2, 3** — with conformance cases 1–18
  green.
- ✅ **Scratch trio implemented on all four production `SessionStore`
  adapters** (Postgres, D1, DynamoDB, Durable Object), each opted into
  the `supportsScratch` conformance cases (Phase 1.5, done
  2026-05-15). This was the production-usability gate; it is cleared.
- Explicit `SubjectConfirmationData/@Recipient` check landed
  (gauntlet item 6, Phase 2 — the one deliberately-deferred Phase 1
  gauntlet item).
- ⏳ Okta + Entra dev-tenant integration tests in CI (gated behind env
  creds; documented setup), run against a real production adapter.
  **Deferred (owner decision, 2026-05-15)** — open TODO, not yet met;
  needs real dev-tenant credentials. The Postgres-backed end-to-end
  SAML test (`acs-postgres.test.ts`) covers the production-adapter
  half against signed fixtures; only the live-IdP half is outstanding.
- `INTEGRATION.md` § SAML SP covers: install, Node-only constraint,
  the scratch-adapter requirement, per-tenant configuration shape,
  IdP-initiated setup, SLO setup, attribute-mapping cookbook.
- `ARCHITECTURE.md` updated with: SAML-AD1–AD7, the two framework
  changes (`methodScratch`, POST-body state recovery), IdP-initiated
  synthetic-flow note.
- Public-API leak test forbids `@node-saml/*` and `xml-crypto` types
  from the root entry.
- Changeset entry following the established "describe by standard/name,
  not phase number" convention.

## House-Style Notes (apply across all SAML code)

- **CJS interop via default-import + destructure.** Every package in
  the SAML dep tree is CJS-only (no `type: "module"`, no `exports`
  field). Don't rely on Node's named-export heuristic for CJS:

  ```ts
  // Avoid — heuristic-dependent across runtimes:
  import { SAML, generateServiceProviderMetadata } from "@node-saml/node-saml"

  // Use — works reliably under Node ESM, Bun, and bundlers:
  import nodeSaml from "@node-saml/node-saml"
  const { SAML, generateServiceProviderMetadata } = nodeSaml
  ```

  Same pattern for `xml-encryption`, `@xmldom/xmldom`, etc. if any
  direct imports ever land (the wrapper should not need them — go
  through node-saml).

- **No third-party types in our public API.** Reuse the existing leak
  test (`test/types/public-api-no-thirdparty-leaks.test.ts`); SAML
  Phase 1 adds `@node-saml/*`, `xml-crypto`, `@xmldom/*`, and
  `xml-encryption` to the forbidden list. The wrapper translates
  node-saml's `Profile` into our `SamlSpProperties` at the boundary.

## First Concrete Step (kick off Phase 1) — historical, all complete

> Superseded by _Status & Resume Point_ (top of doc). Kept for the
> record; steps 1–4 are all done. Do not act on this section when
> resuming — read the Status block instead.

1. ✅ Dependency audit complete. Pins selected: `@node-saml/node-saml@5.1.0`,
   `xml-crypto@6.1.2` (transitive, locked by node-saml). Build script
   (`Bun.build({ format: "esm", external: ["*"] })` + `tsc` for types)
   handles CJS deps via `external: ["*"]`; no bundler changes needed.
2. Land the `methodScratch` precursor PR: add to `MethodContext`,
   wire `SessionStore`-backed default and an in-memory test impl.
   Time-box: one day.
3. Land an empty `src/methods/saml-sp/` directory scaffold + the
   Node-only subpath export + the negative public-API-leak test.
   This establishes the boundary before any real code lands.
   Time-box: half a day.
4. Begin the gauntlet implementation, fixture-first: write the failing
   tests for items 1–11 against hand-built bad XML, then implement.
