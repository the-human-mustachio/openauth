---
"@_mustachio/openauth": minor
---

SAML SP interop hardening — authentication-context control, an entityID override, configurable signature posture, and richer `AuthnStatement` facts.

**Behaviour change: `RequestedAuthnContext` is no longer sent by default.** Previously the outbound `AuthnRequest` inherited the underlying library's defaults and always carried `<RequestedAuthnContext Comparison="exact">` demanding `PasswordProtectedTransport`. An IdP running an MFA sign-on policy can answer that with `NoAuthnContext` instead of a login. The SP now sends no `RequestedAuthnContext` unless you ask for one, letting the IdP apply its own policy. If you relied on the old behaviour, set it explicitly.

**What's new:**

- **`requestedAuthnContext`** — request specific authentication context classes (e.g. MFA) with `classRefs` and an optional `comparison` (`exact` | `minimum` | `maximum` | `better`, default `exact`). `minimum` is usually the safer choice when the goal is "at least MFA".
- **`SamlSpProperties.authnContextClassRef`** — what the IdP *actually* asserted, read from the signed assertion. Requesting a context is not proof one was used; step-up decisions belong on this value.
- **`forceAuthn`** — sets `ForceAuthn="true"` on the `AuthnRequest`. A request only: SAML obliges the IdP to nothing and the Response carries no proof, so it is not evidence of fresh authentication.
- **`spEntityId`** — override the derived SP entityID to adopt one that already exists at the IdP, so an existing SAML app can be migrated without the customer editing their production SSO config. The override flows to the `AuthnRequest`, audience validation, SP metadata, and logout messages through a single resolver, so published metadata stays truthful.
- **`requireSignedAssertion` / `requireSignedResponse`** — configurable signature posture. Defaults are unchanged (signed assertion required, Response signature not), and now support both defence-in-depth (`requireSignedResponse: true`) and IdPs that sign only the `<Response>`. Turning both off is rejected by the config schema. `WantAssertionsSigned` in SP metadata follows the setting rather than being hardcoded.
- **`SamlSpProperties.sessionNotOnOrAfter`** — the IdP's `AuthnStatement/@SessionNotOnOrAfter` as Unix ms, when supplied. The library does not act on it; hosts wanting "when their IdP session ends, ours ends" clamp their own session/token TTL to it in `success`.

**Fixed.** `SamlSpProperties.authnInstant` is now read from the assertion's `AuthnInstant`. It was documented as the assertion's value but silently fell back to the current time, because the underlying library's profile never carried it.

**Internal.** The ACS parsed the verified assertion three times (Recipient check, replay dedup, and now the `AuthnStatement` read); it parses once and shares the document.
