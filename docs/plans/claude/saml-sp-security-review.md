# SAML SP — Internal Security Review

Companion to `saml-sp-plan.md`. Walks the **OASIS SAML 2.0 Security
and Privacy Considerations** + the **OWASP SAML Security Cheat Sheet**
against the `@_mustachio/openauth` SAML SP implementation on
`feat/saml-sp`. Each row: the threat, our control, and where it is
exercised. "Residual" rows are accepted, documented gaps with a
mitigation — not unknowns.

Scope: SP role only (`SAML-AD1`). Signature/canonicalization/XML
parsing is delegated to pinned `@node-saml/node-saml@5.1.0` +
`xml-crypto@6.1.2` (CVE history is load-bearing — pin bumps require
re-running the gauntlet, per the plan).

## Signature & message integrity

| Threat | Control | Evidence |
| --- | --- | --- |
| Unsigned assertion accepted | `wantAssertionsSigned: true`; node-saml verifies only `getSignedReferences()` bytes | `acs.test.ts` "unsigned assertion" |
| Wrong-key / forged signature | Verify against pinned `idp.signingCerts` only | `acs.test.ts` "signed with wrong key"; `sls-http.test.ts` forged LogoutRequest; `slo-initiate-http.test.ts` forged LogoutResponse |
| XML Signature Wrapping (XSW1–8) | xml-crypto `getSignedReferences()` path; single-assertion enforcement | `acs.test.ts` "signature-wrapping (XSW)" |
| Signature exclusion / comment truncation | node-saml@5.1.0 (patches CVE-2025-54369/54419); xml-crypto@6.1.2 (CVE-2025-29774/29775) | pinned exact versions; `saml-sp-no-thirdparty-leaks` guards surface |
| Encrypted assertion bypasses signature check | Decrypted assertion's XML-DSig still fully enforced (`wantAssertionsSigned` applies post-decrypt) | `acs-encrypted.test.ts` "flag ON … signature still enforced" |

## Message scope & confused-deputy

| Threat | Control | Evidence |
| --- | --- | --- |
| XXE / external entity into subject | `@xmldom/xmldom` (no entity expansion); subject read from verified bytes | `acs.test.ts` "XXE" (no `root:` / `/bin/` leak) |
| Audience / recipient confusion (assertion replayed to another SP) | `AudienceRestriction` (node-saml) + explicit `SubjectConfirmationData/@Recipient` check vs the exact committed ACS | `acs.test.ts` "audience mismatch", "recipient mismatch", "recipient absent" (`checkRecipient`) |
| Stale / pre-dated assertion | `NotBefore` / `NotOnOrAfter` + `clockSkewSeconds` | `acs.test.ts` "expired conditions" |
| Wrong IdP (`Issuer` spoof) | `idpIssuer` enforced by node-saml | covered via fixture `idpEntityId` mismatch path |

## Replay

| Threat | Control | Evidence |
| --- | --- | --- |
| SP-initiated assertion replay | `InResponseTo` single-use via `methodScratch`-backed cache (cross-node) | `acs.test.ts` + `acs-postgres.test.ts` "replay rejected" |
| IdP-initiated assertion replay (no `InResponseTo`) | Explicit assertion-`@ID` dedup via `methodScratch`, TTL = `NotOnOrAfter` + skew (clamped) | `idp-initiated.test.ts` |
| Front-channel `LogoutRequest` replay | `LogoutRequest @ID` dedup via `methodScratch` | `sls-http.test.ts` "replay … 2nd rejected" |
| Scratch store unavailable ⇒ fail-open replay | Fail-closed: `error` rather than skip the check | `acs.ts` (replay record failure → `internal_error`); `authnrequest.ts` scratch probe |

## Open redirect & flowless surface

| Threat | Control | Evidence |
| --- | --- | --- |
| `RelayState` as open-redirect | `RelayState` never a redirect target; IdP-init redirect is the config-validated `defaultRedirectUri`, re-checked vs the registered client | `ARCHITECTURE.md` §`unsolicitedCallback`; Phase 2 IdP-init tests |
| Anonymous public routes used to authenticate | `handlePublicMethodRoute` re-checks `publicRoutes` (fail-closed) and refuses a flowless `success` | `method-route-public.test.ts` |
| Privileged side effect on an anonymous route (SLO token revoke) | Gated by node-saml signature verification; host-directed revocation only; throwing hook / failed revoke fails closed (no `LogoutResponse`) | `method-route-public.test.ts` upstream-logout block; `sls-http.test.ts` |
| Forced logout via SP-initiated `/logout` (CSRF) | **Residual (host-owned).** The route is anonymous at the library boundary and emits a signed `LogoutRequest` for the posted `nameId`. Mitigation: `POST`-only (no drive-by GET/prefetch); documented host contract — invoke only for the authenticated subject, that subject's own `NameID`, behind host CSRF. The library cannot authenticate the caller without owning a session it deliberately does not (`SAML-AD3` boundary). | `INTEGRATION.md` §9.5 "Security"; `slo-initiate.ts` doc header |

## Logout integrity

| Threat | Control | Evidence |
| --- | --- | --- |
| Forged `LogoutRequest` logs a user out | XML-DSig verified vs `idp.signingCerts`; forged → 403, zero side effect | `sls-http.test.ts` "forged … denied, no side effect" |
| `LogoutResponse` spoof on SP-initiated return | `validate*` signature-verified; forged → denied | `slo-initiate-http.test.ts` "forged LogoutResponse → denied" |
| SLO advertised but not serveable | `/sls` + `/logout` public **iff** `idp.sloUrl`; metadata advertises `SingleLogoutService` iff configured | `sls-http.test.ts` gating + metadata tests |

## Key handling

- SP signing (`signingKey`) and decryption (`decryptionKey`) private
  keys are per-connection `MethodStore` config, decoupled from the
  OIDC `KeyStore` (`SAML-AD` O3). Documented as secrets requiring
  at-rest encryption / host resolver — `INTEGRATION.md` §9.5,
  `types.ts` doc comments. No private key is logged or surfaced in any
  audit event (audit payloads carry ids only — `audit-log.ts` rule).

## Audit mapping (decision record)

The plan sketched SAML-named events (`saml_response_verified`, …).
**Decision: no SAML-specific kinds are added to the `AuditLog` port** —
that would be SAML-specific surface in a deliberately general port,
contradicting `SAML-AD3` ("SAML is just a method, no parallel
framework") and the project boundary. SAML observability rides the
existing **general** events:

| Wished-for | Actual general event |
| --- | --- |
| `saml_authn_request_built` / `_response_verified` | `authorize_started` / `authorize_succeeded` / `token_issued` (carry `methodId`/`methodKind="saml-sp"`) |
| `saml_response_rejected{reason}` / `saml_replay_detected` | `authorize_failed{reason}` (reason carries node-saml's message / "replay detected …") |
| `saml_logout_completed` | `session_logout { via: "upstream_slo", methodId, methodKind, subjectId? }` (3b) + `token_revoked { reason: "subject_revoke" }` when a subject was revoked |

**Residual:** a *failed* upstream-logout attempt (forged/replayed
`LogoutRequest`) surfaces only as an HTTP 403 on the anonymous public
route, not a typed audit event — distinguishing it from a denied
`/metadata` request would require new method/port surface
(`SAML-AD3`). Mitigation: SIEM alerting on 403s to `/m/*/sls`; the
*successful* SLO path **is** audited (`session_logout`).

## Out of scope (declared non-goals — `saml-sp-plan.md`)

SAML IdP role; edge runtimes (Node-only); Holder-of-Key; ECP;
Artifact binding; **back-channel (SOAP) SLO**. Each is a documented
non-goal, not an oversight.

## Verification posture

Hand-built gauntlet (matrix cases 1–18, all ✅) driven end-to-end
through `dispatchMethod` / the real router — no OASIS interop suite
(matches `idp-rebuild-plan.md` §Conformance Scope). Live Okta/Entra
dev-tenant test is the one tracked, owner-deferred follow-up (needs
real credentials; not a sequencing blocker).
