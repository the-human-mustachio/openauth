/**
 * Assertion Consumer Service — the inbound, security-critical half.
 *
 * Mounted at the `"GET /callback"` route key (the framework's
 * universal `/cb/<methodId>` callback, GET+POST). By the time this
 * runs, `handleCallback` has already MAC-verified the state envelope
 * (carried as `RelayState`) and consumed the flow; `ctx.flow` is the
 * consumed record and `ctx.methodState` carries the SP entityID + ACS
 * URL we committed to at AuthnRequest time.
 *
 * The cryptographic gauntlet (XML-DSig verification on signed
 * references only, XSW/XXE resistance, issuer/audience,
 * NotBefore/NotOnOrAfter, InResponseTo single-use) is delegated to
 * `@node-saml/node-saml`'s `validatePostResponseAsync` — the
 * CVE-2025-54369/54419-hardened path (SAML-AD1). We do not
 * reimplement XML-DSig. Any verification failure surfaces as a thrown
 * error which we map to a controlled `denied`; only infrastructure /
 * misconfiguration faults become `error`.
 *
 * `SubjectConfirmationData/@Recipient` (gauntlet item 6) is **not**
 * enforced by node-saml, so it is checked here explicitly against the
 * signed assertion — see `checkRecipient`.
 *
 * Replay: for SP-initiated flows, node-saml's `validateInResponseTo:
 * always` + the `methodScratch`-backed cache make the `InResponseTo`
 * single-use, so a replayed Response fails (its request id was already
 * consumed). Explicit assertion-ID dedup is only required for
 * IdP-initiated SSO and lands with that work in Session 2.
 */
// CJS interop per the SAML house-style note — default-import then
// destructure rather than relying on the named-export heuristic.
import xmldom from "@xmldom/xmldom"

import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"

import { mapProfile, type VerifiedProfile } from "./attributes"
import { buildSamlInstance } from "./saml-instance"
import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

const { DOMParser } = xmldom

type NodeSamlProfile = {
  nameID?: string
  nameIDFormat?: string
  sessionIndex?: string
  attributes?: Record<string, unknown>
  getSamlResponseXml?: () => string
  /** The signed assertion XML — the bytes xml-crypto verified. */
  getAssertionXml?: () => string
}

/**
 * Gauntlet item 6 — `SubjectConfirmationData/@Recipient`.
 *
 * node-saml enforces Issuer, AudienceRestriction,
 * Conditions/SubjectConfirmation timestamps and `InResponseTo`, but it
 * does **not** validate `@Recipient`. The SAML 2.0 Web Browser SSO
 * profile (§4.1.4.3) requires a bearer `SubjectConfirmationData` whose
 * `Recipient` is the ACS the assertion was delivered to. We read it
 * from the **signed** assertion (`getAssertionXml()` — the verified
 * bytes, never the unsigned outer Response) and compare to the exact
 * ACS URL committed at AuthnRequest time. A real xml-crypto-verified
 * DOM parse, not an xml2js-shape walk (which the plan rejected as more
 * fragile than the documented gap).
 *
 * Returns `null` when the check passes; otherwise a non-`success`
 * `MethodResult` (`denied` for a binding failure, `error` for a
 * library/infra fault — matching the rest of this handler's
 * classification).
 */
function checkRecipient(
  profile: NodeSamlProfile,
  acsUrl: string,
): MethodResult<SamlSpProperties, SamlSpState> | null {
  if (typeof profile.getAssertionXml !== "function") {
    // node-saml v5.1 populates this on a successful verify. Its
    // absence means the library contract changed under us — fail loud
    // rather than skip a security check we now promise.
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: node-saml profile exposes no getAssertionXml(); cannot " +
          "perform the Recipient binding check. Refusing to authenticate.",
      ),
    }
  }

  let doc: Document
  try {
    doc = new DOMParser().parseFromString(
      profile.getAssertionXml(),
      "text/xml",
    ) as unknown as Document
  } catch (e) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: failed to parse the verified assertion for the " +
          "Recipient check",
        e,
      ),
    }
  }

  // Namespace-agnostic: match by local name regardless of prefix.
  const nodes = doc.getElementsByTagNameNS(
    "*",
    "SubjectConfirmationData",
  )
  const recipients: string[] = []
  for (let i = 0; i < nodes.length; i++) {
    const r = nodes[i]?.getAttribute("Recipient")
    if (r) recipients.push(r)
  }

  if (recipients.length === 0) {
    return {
      kind: "denied",
      reason:
        "assertion has no SubjectConfirmationData/@Recipient binding it " +
        "to this ACS",
    }
  }
  if (!recipients.includes(acsUrl)) {
    return {
      kind: "denied",
      reason: "recipient mismatch: assertion not addressed to this ACS",
    }
  }
  return null
}

export async function consumeAssertion(
  ctx: MethodContext<SamlSpState>,
  config: SamlSpConfig,
): Promise<MethodResult<SamlSpProperties, SamlSpState>> {
  const state = ctx.methodState
  if (!state || !state.spEntityId || !state.acsUrl) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: ACS reached without AuthnRequest method state " +
          "(spEntityId / acsUrl). The flow did not originate from this method.",
      ),
    }
  }

  let samlResponse: string | null
  let relayState: string | null
  try {
    const form = new URLSearchParams(await ctx.request.text())
    samlResponse = form.get("SAMLResponse")
    relayState = form.get("RelayState")
  } catch {
    return {
      kind: "error",
      error: authError.internalError("saml-sp: ACS could not read POST body"),
    }
  }
  if (!samlResponse) {
    return { kind: "denied", reason: "missing SAMLResponse" }
  }

  // Build is a configuration concern (e.g. no signing cert within its
  // validity window, or a rotation gap). A throw here is an operator
  // fault, NOT a user auth failure — surfacing it as `denied` would
  // hide a misconfiguration behind per-user "access denied" noise.
  let saml: ReturnType<typeof buildSamlInstance>
  try {
    saml = buildSamlInstance(
      config,
      {
        spEntityId: state.spEntityId,
        acsUrl: state.acsUrl,
        scratch: ctx.methodScratch,
      },
      Date.now(),
    )
  } catch (e) {
    return {
      kind: "error",
      error: authError.internalError(
        `saml-sp: cannot construct verifier: ${
          e instanceof Error ? e.message : String(e)
        }`,
        e,
      ),
    }
  }

  let profile: NodeSamlProfile | null
  try {
    const result = await saml.validatePostResponseAsync({
      SAMLResponse: samlResponse,
      ...(relayState !== null ? { RelayState: relayState } : {}),
    })
    profile = result.profile as NodeSamlProfile | null
  } catch (e) {
    // Every node-saml verification failure (bad/absent signature,
    // signature-wrapping, issuer/audience mismatch, expired
    // conditions, unknown InResponseTo) throws here. These are
    // controlled auth failures, not server faults.
    return {
      kind: "denied",
      reason: `assertion rejected: ${
        e instanceof Error ? e.message : String(e)
      }`,
    }
  }

  if (!profile || !profile.nameID) {
    return { kind: "denied", reason: "assertion produced no usable subject" }
  }

  // Gauntlet item 6 — node-saml does not enforce @Recipient; we do,
  // against the exact ACS URL the IdP saw in the AuthnRequest.
  const recipientFailure = checkRecipient(profile, state.acsUrl)
  if (recipientFailure) return recipientFailure

  const verified: VerifiedProfile = {
    nameID: profile.nameID,
    nameIDFormat: profile.nameIDFormat ?? "",
    ...(profile.sessionIndex !== undefined
      ? { sessionIndex: profile.sessionIndex }
      : {}),
    attributes: profile.attributes ?? {},
    responseXml: profile.getSamlResponseXml?.() ?? "",
  }

  const mapped = mapProfile(verified, config.attributeMapping)
  if ("error" in mapped) {
    return { kind: "denied", reason: mapped.error }
  }

  return {
    kind: "success",
    providerSubject: mapped.providerSubject,
    properties: mapped.properties,
  }
}
