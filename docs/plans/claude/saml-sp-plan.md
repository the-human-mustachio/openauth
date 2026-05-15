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
`node:crypto` and there is no realistic edge path. Build in three
sessions: SP-initiated SSO + verification gauntlet → IdP-initiated SSO +
SP metadata → Single Logout. Total estimated effort: 6–8 weeks.

## Status & Resume Point

> **Maintain this block every working session.** It is the first thing
> to read when resuming with fresh context. The per-phase ✅ markers
> further down are the detailed ledger; this is the summary + the next
> action.

**As of 2026-05-15** — branch `feat/saml-sp`, 6 commits ahead of
`master` (`a994894`..`1509822`), nothing pushed, nothing merged.

**Done:** SAML Phase 1 (SP-initiated SSO) complete and independently
security-reviewed. End-to-end working: `/authorize` → IdP →
signed-assertion POST → node-saml verification gauntlet → mapped
subject → host `success` callback. Review findings all fixed
(`1509822`). Full suite green; `tsc` strict clean; root entry verified
edge-clean.

**Not production-usable yet — one hard blocker:** SAML requires a
`SessionStore` implementing the `saveScratch/readScratch/deleteScratch`
trio (backs InResponseTo replay protection). **Only the in-memory
adapter implements it.** Postgres / D1 / DynamoDB / Durable-Object
adapters do not. SAML fail-fasts loudly on those. In-memory = single-
process dev only.

**Recommended next action (highest leverage toward actually-usable):**
implement the scratch trio on the production `SessionStore` adapters
(Postgres, D1, DynamoDB, Durable Object), following the existing
optional-method pattern (mirror `savePar`/`consumePar`). Then a live
Okta/Entra integration test. Only after that does Phase 2 (IdP-
initiated + SP metadata + explicit Recipient check + signed-
AuthnRequest/KeyStore wiring) and Phase 3 (SLO) make sense.

**Two framework changes SAML drove** (documented in `ARCHITECTURE.md`):
`MethodContext.methodScratch` (precursor commit `395ec99`) and
`handleCallback` POST-body state recovery (`db45ab6`, general — also
unblocks OAuth `form_post`).

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
  samlSpFactory,
  parseSamlIdpMetadata,
  type SamlSpConfig,
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

```
packages/openauth/
├── src/
│   └── methods/
│       └── saml-sp/
│           ├── factory.ts               # samlSpFactory — kind: "saml-sp"
│           ├── authnrequest.ts          # build + sign AuthnRequest
│           ├── acs.ts                   # verify Response, run gauntlet
│           ├── metadata.ts              # SP metadata XML
│           ├── replay.ts                # SessionStore-backed replay guard
│           ├── attributes.ts            # SamlAttributeMapping → properties
│           ├── parse-idp-metadata.ts    # public helper
│           └── types.ts                 # exported types
└── test/
    ├── methods/saml-sp/
    │   ├── factory.test.ts
    │   ├── authnrequest.test.ts
    │   ├── acs.test.ts                  # signature gauntlet, attribute mapping
    │   ├── attack-xsw.test.ts           # XSW1–XSW8 fixtures
    │   ├── attack-xxe.test.ts
    │   ├── attack-comment-truncation.test.ts
    │   ├── replay.test.ts
    │   └── fixtures/                    # hand-built Response XML + attack variants
    └── conformance/
        └── saml-sp.test.ts              # OASIS-flavored interop cases
```

This mirrors the existing pattern: methods are flat under
`src/methods/` for trivial wrappers and gain their own subdirectory when
internal structure justifies it (cf. `methods/providers/`). SAML's
internals (request building, ACS, metadata, replay, attribute mapping)
justify the subdirectory.

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
| `GET /callback`    | IdP HTTP-POST to `/cb/<methodId>` (universal) | Verify Response — the full gauntlet. Returns `success` / `denied` / `error`.                                                               | Next increment |

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
  precursor PR. Memory adapter backs it; production adapters add the
  trio when first deployed against SAML.
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
- Live integration test (gated behind env-var creds) against an Okta
  dev tenant; documented in `INTEGRATION.md` § SAML SP. **(After the
  gauntlet — needs the ACS to be real.)**

**Acceptance criteria:**

- All 11 gauntlet items have ≥1 failing-fixture test that the verifier
  rejects.
- Okta dev tenant integration green end-to-end: AuthnRequest →
  Response → `MethodResult.success` → host `success` callback fires
  with mapped `SubjectClaim`.
- `bunx tsc --noEmit` exits 0 under strict.
- Edge-import test still passes (no SAML transitive in root bundle).

**Risks:**

- `@node-saml/node-saml` API surface change between versions. **Mitigation:**
  pin to exact patch version, add a smoke test that fails if a major
  bump silently changes the signed-references API contract.
- Attribute mapping spec drift across IdPs. **Mitigation:** ship Okta
  + Entra fixtures in tests; document the "if it isn't here, add a
  custom mapper" escape hatch.

**Estimated effort:** 3 weeks.

---

### SAML Phase 2 — IdP-initiated SSO + SP metadata + cert rotation

**Goal:** Cover the Okta-default IdP-initiated flow and publish SP
metadata that enterprise IdPs can import without manual fiddling.

**Deliverables:**

- `idpInitiated` config branch + synthetic-flow path (SAML-AD7).
  Documented end-to-end: how the framework synthesizes
  `FlowRecord.{clientId, redirectUri, scopes}` from `SamlSpConfig.idpInitiated`,
  what the audit log emits, how this composes with the existing
  `success` callback.
- `GET /metadata` route returning standards-compliant SP metadata XML
  with our entityID, ACS URL, NameIDFormat preference, signing cert
  (if `signAuthnRequest: true`).
- Hot cert rotation — `SamlSpConfig.idp.signingCerts` accepts ≥1
  certs; verifier accepts any cert in its validity window. Tests cover
  overlap windows.
- `parseSamlIdpMetadata(xml)` public helper — pure function, parses
  an IdP metadata XML doc into the `SamlSpConfig.idp` shape so hosts
  can implement "paste metadata URL or XML" UI without owning the XML
  parsing.
- Test suite extensions: `idp-initiated.test.ts`, `metadata.test.ts`,
  `cert-rotation.test.ts`, `parse-idp-metadata.test.ts`.
- `INTEGRATION.md` § SAML SP extended with IdP-initiated configuration
  walkthrough.

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

**Deliverables:**

- Front-channel SLO: `GET/POST /sls` routes implementing
  `LogoutRequest` verification + `LogoutResponse` emission.
- `SessionIndex` tracking on success (Phase 1 already captures it on
  `SamlSpProperties`; Phase 3 wires it through to `SessionStore` so
  SLO can revoke the right session).
- Encrypted-assertion support **behind a feature flag**
  (`SamlSpConfig.allowEncryptedAssertions: boolean`, default `false`).
  Uses `@node-saml/node-saml`'s `xml-encryption` integration.
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
- SAML Phase 1 → 2 → 3 are strictly sequential; each builds on the
  previous.
- SAML work is **parallelizable with** remaining IdP Phase 8 sessions
  (DPoP, PAR, mTLS, DCR, rate limiting, logging/tracing) because they
  touch disjoint code paths. SAML touches `src/methods/`, `src/types/`,
  `src/http/router.ts` (route mounting), and adds tests; Phase 8
  sessions touch `src/domain/`.
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

Hand-built test matrix under `test/conformance/saml-sp.test.ts`,
following the existing pattern (`oauth-dpop.test.ts`,
`oauth-par.test.ts`, `oidc-core.test.ts`). Cases:

| # | Case                                              | Phase |
| - | ------------------------------------------------- | ----- |
| 1 | SP-initiated SSO end-to-end (Okta fixture)        | 1     |
| 2 | SP-initiated SSO end-to-end (Entra fixture)       | 1     |
| 3 | Unsolicited Response without `idpInitiated`       | 1     |
| 4 | Missing signature → `denied: "unsigned"`          | 1     |
| 5 | Wrong-cert signature → `denied: "signature"`      | 1     |
| 6 | Audience mismatch → `denied: "audience"`          | 1     |
| 7 | Recipient mismatch → `denied: "recipient"`        | 1     |
| 8 | Stale `NotOnOrAfter` → `denied: "expired"`        | 1     |
| 9 | Replayed assertion ID → `denied: "replay"`        | 1     |
| 10| XSW2 wrapping attack → `denied: "signature"`      | 1     |
| 11| XXE entity expansion → parser error               | 1     |
| 12| IdP-initiated success with `defaultClientId`      | 2     |
| 13| IdP-initiated with hostile `RelayState`           | 2     |
| 14| SP metadata XML matches IdP-importer expectations | 2     |
| 15| Cert rotation: old + new cert both valid          | 2     |
| 16| Front-channel SLO round-trip                      | 3     |
| 17| Encrypted assertion off → rejected                | 3     |
| 18| Encrypted assertion on → accepted                 | 3     |

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
3. **Do we want a `SamlEventEmitter` port for SLO push** (so the host
   can fan out logout to other systems)? Defer until a concrete
   deployment asks. Today's audit log covers the observability
   minimum.
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

- All three sessions shipped, with conformance cases 1–18 green.
- Okta + Entra dev-tenant integration tests in CI (gated behind env
  creds; documented setup procedure for contributors).
- `INTEGRATION.md` § SAML SP covers: install, Node-only constraint,
  per-tenant configuration shape, IdP-initiated setup, SLO setup,
  attribute mapping cookbook.
- `ARCHITECTURE.md` updated with: SAML-AD1–AD7, `methodScratch`
  decision, IdP-initiated synthetic-flow note.
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

## First Concrete Step (kick off Phase 1)

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
