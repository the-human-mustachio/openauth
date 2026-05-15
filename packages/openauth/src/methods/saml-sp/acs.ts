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
 * references only, XSW/XXE resistance, issuer/audience/recipient,
 * NotBefore/NotOnOrAfter, InResponseTo single-use) is delegated to
 * `@node-saml/node-saml`'s `validatePostResponseAsync` — the
 * CVE-2025-54369/54419-hardened path (SAML-AD1). We do not
 * reimplement XML-DSig. Any verification failure surfaces as a thrown
 * error which we map to a controlled `denied`; only infrastructure /
 * misconfiguration faults become `error`.
 *
 * Replay: for SP-initiated flows, node-saml's `validateInResponseTo:
 * always` + the `methodScratch`-backed cache make the `InResponseTo`
 * single-use, so a replayed Response fails (its request id was already
 * consumed). Explicit assertion-ID dedup is only required for
 * IdP-initiated SSO and lands with that work in Session 2.
 */
import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"

import { mapProfile, type VerifiedProfile } from "./attributes"
import { buildSamlInstance } from "./saml-instance"
import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

type NodeSamlProfile = {
  nameID?: string
  nameIDFormat?: string
  sessionIndex?: string
  attributes?: Record<string, unknown>
  getSamlResponseXml?: () => string
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
