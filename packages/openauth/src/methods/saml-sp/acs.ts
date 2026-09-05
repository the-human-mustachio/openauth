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
 * Two modes, discriminated by `ctx.flow`:
 *
 *   - **SP-initiated** (`ctx.flow` set): `handleCallback` MAC-verified
 *     the state envelope and consumed the flow; binding (SP entityID +
 *     ACS) comes from `ctx.methodState` committed at AuthnRequest time.
 *     `InResponseTo` is single-use (`always` + the scratch cache), so a
 *     replayed Response fails on its already-consumed request id.
 *   - **IdP-initiated** (`ctx.flow === null`): an unsolicited Response,
 *     no AuthnRequest, no state envelope, no flow. Allowed only when
 *     the instance configured `idpInitiated` (the framework gates this
 *     via `AuthMethod.unsolicitedCallback`). Binding is *derived* from
 *     `ctx.dispatch` (issuer/ACS — same derivation as AuthnRequest /
 *     metadata, so no drift). `InResponseTo` is `ifPresent` (none
 *     exists), so single-use no longer covers replay — we add explicit
 *     **assertion-ID dedup** via `methodScratch` (TTL = the assertion's
 *     `NotOnOrAfter` + skew). Success carries `unsolicitedBinding` from
 *     `config.idpInitiated` for the framework to mint the code.
 */
// CJS interop per the SAML house-style note — default-import then
// destructure rather than relying on the named-export heuristic.
import xmldom from "@xmldom/xmldom"

import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"

import { mapProfile, type VerifiedProfile } from "./attributes"
import { buildSamlInstance, resolveSpEntityId } from "./saml-instance"
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
function parseVerifiedAssertion(
  profile: NodeSamlProfile,
):
  | { doc: Document }
  | { failure: MethodResult<SamlSpProperties, SamlSpState> } {
  if (typeof profile.getAssertionXml !== "function") {
    // node-saml v5.1 populates this on a successful verify. Its
    // absence means the library contract changed under us — fail loud
    // rather than skip security checks we now promise.
    return {
      failure: {
        kind: "error",
        error: authError.internalError(
          "saml-sp: node-saml profile exposes no getAssertionXml(); cannot " +
            "perform the Recipient binding check. Refusing to authenticate.",
        ),
      },
    }
  }
  try {
    return {
      doc: new DOMParser().parseFromString(
        profile.getAssertionXml(),
        "text/xml",
      ) as unknown as Document,
    }
  } catch (e) {
    return {
      failure: {
        kind: "error",
        error: authError.internalError(
          "saml-sp: failed to parse the verified assertion",
          e,
        ),
      },
    }
  }
}

function checkRecipient(
  doc: Document,
  acsUrl: string,
): MethodResult<SamlSpProperties, SamlSpState> | null {
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

/**
 * For IdP-initiated replay dedup: pull the assertion `@ID` and the
 * tightest `NotOnOrAfter` from the **verified** assertion (the same
 * parsed document every other check reads). Returns `null` when the
 * assertion carries no `@ID` — the caller treats that as a fail-loud
 * error rather than skipping replay protection we promised.
 */
function extractReplayInfo(
  doc: Document,
): { assertionId: string; notOnOrAfterMs: number | null } | null {
  const root = doc.documentElement
  const assertionId = root?.getAttribute("ID") ?? ""
  if (!assertionId) return null
  let earliest: number | null = null
  for (const tag of ["Conditions", "SubjectConfirmationData"]) {
    const els = doc.getElementsByTagNameNS("*", tag)
    for (let i = 0; i < els.length; i++) {
      const v = els[i]?.getAttribute("NotOnOrAfter")
      if (!v) continue
      const ms = Date.parse(v)
      if (!Number.isNaN(ms)) earliest = earliest === null ? ms : Math.min(earliest, ms)
    }
  }
  return { assertionId, notOnOrAfterMs: earliest }
}

/**
 * Read the `<AuthnStatement>` facts the host needs but node-saml's
 * `Profile` does not carry (`types.d.ts` exposes `nameID`,
 * `nameIDFormat`, `sessionIndex` and the flattened attributes, and
 * nothing else structural).
 *
 * Read from the **verified** assertion document — never the unsigned
 * outer Response — for the same reason `checkRecipient` is: an
 * attacker-controlled value outside the signature is not a fact.
 *
 * All three are optional in SAML, so every field is best-effort; the
 * caller falls back rather than failing, since none of them is a
 * security control on its own.
 */
function extractAuthnStatement(doc: Document): {
  authnInstant?: string
  sessionNotOnOrAfter?: number
  authnContextClassRef?: string
} {
  const out: {
    authnInstant?: string
    sessionNotOnOrAfter?: number
    authnContextClassRef?: string
  } = {}
  const stmt = doc.getElementsByTagNameNS("*", "AuthnStatement")[0]
  if (!stmt) return out

  const instant = stmt.getAttribute("AuthnInstant")
  if (instant) out.authnInstant = instant

  const sessionExpiry = stmt.getAttribute("SessionNotOnOrAfter")
  if (sessionExpiry) {
    const ms = Date.parse(sessionExpiry)
    if (!Number.isNaN(ms)) out.sessionNotOnOrAfter = ms
  }

  const ref = stmt
    .getElementsByTagNameNS("*", "AuthnContextClassRef")[0]
    ?.textContent?.trim()
  if (ref) out.authnContextClassRef = ref

  return out
}

export async function consumeAssertion(
  ctx: MethodContext<SamlSpState>,
  methodId: string,
  config: SamlSpConfig,
): Promise<MethodResult<SamlSpProperties, SamlSpState>> {
  // Discriminator: a consumed flow ⇒ SP-initiated; no flow ⇒ an
  // unsolicited IdP-initiated POST (the framework only routes one here
  // when this instance opted in via `unsolicitedCallback`).
  const idpInitiated = ctx.flow === null

  let spEntityId: string
  let acsUrl: string
  if (idpInitiated) {
    if (!config.idpInitiated) {
      // Fail-closed: should be unreachable (the framework gates on
      // `unsolicitedCallback`, set only when idpInitiated is config'd).
      return {
        kind: "error",
        error: authError.internalError(
          "saml-sp: unsolicited Response reached a method with no " +
            "idpInitiated config",
        ),
      }
    }
    if (!ctx.dispatch) {
      return {
        kind: "error",
        error: authError.internalError(
          "saml-sp: IdP-initiated ACS dispatched without issuer context",
        ),
      }
    }
    // Same derivation as AuthnRequest / metadata — no drift.
    spEntityId = resolveSpEntityId(
      config,
      ctx.dispatch.issuerUrl,
      ctx.tenant.id,
      methodId,
    )
    acsUrl = ctx.dispatch.callbackUrl
  } else {
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
    spEntityId = state.spEntityId
    acsUrl = state.acsUrl
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
        spEntityId,
        acsUrl,
        scratch: ctx.methodScratch,
        ...(idpInitiated ? { idpInitiated: true } : {}),
        // Encrypted assertions are opt-in per connection. Absent ⇒ no
        // decryptionPvk ⇒ node-saml rejects an EncryptedAssertion.
        ...(config.allowEncryptedAssertions && config.decryptionKey
          ? { decryptionPvk: config.decryptionKey.privateKeyPem }
          : {}),
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
    const msg = e instanceof Error ? e.message : String(e)
    // node-saml throws this exact message when an EncryptedAssertion
    // arrives but no decryptionPvk is configured. Give the operator a
    // signal that the *connection* is mis/under-configured rather than
    // a generic "assertion rejected".
    if (
      !config.allowEncryptedAssertions &&
      msg.includes("No decryption key")
    ) {
      return {
        kind: "denied",
        reason:
          "encrypted assertion received but encrypted assertions are not " +
          "enabled for this SAML connection (set allowEncryptedAssertions " +
          "+ decryptionKey)",
      }
    }
    return { kind: "denied", reason: `assertion rejected: ${msg}` }
  }

  if (!profile || !profile.nameID) {
    return { kind: "denied", reason: "assertion produced no usable subject" }
  }

  // One parse of the verified assertion, shared by every check below
  // (Recipient binding, IdP-init replay dedup, AuthnStatement facts) —
  // they all read the same signed bytes, so parsing once is both
  // cheaper and impossible to accidentally diverge.
  const parsed = parseVerifiedAssertion(profile)
  if ("failure" in parsed) return parsed.failure
  const assertionDoc = parsed.doc

  // Gauntlet item 6 — node-saml does not enforce @Recipient; we do,
  // against the exact ACS URL the IdP saw (committed for SP-init,
  // derived for IdP-init — identical value either way).
  const recipientFailure = checkRecipient(assertionDoc, acsUrl)
  if (recipientFailure) return recipientFailure

  // IdP-init replay: no InResponseTo single-use to lean on, so dedup
  // the signed assertion's @ID. SP-init does not need this (the
  // request id is already single-use).
  if (idpInitiated) {
    const replay = extractReplayInfo(assertionDoc)
    if (!replay) {
      return {
        kind: "error",
        error: authError.internalError(
          "saml-sp: cannot read assertion @ID for IdP-initiated replay " +
            "protection. Refusing to authenticate.",
        ),
      }
    }
    const key = `idp-replay:${replay.assertionId}`
    const seen = await ctx.methodScratch.get(key)
    if (seen.ok) {
      return {
        kind: "denied",
        reason: "assertion replay detected (assertion ID already seen)",
      }
    }
    const skewMs = (config.clockSkewSeconds ?? 60) * 1000
    const now = Date.now()
    const horizon =
      replay.notOnOrAfterMs !== null
        ? replay.notOnOrAfterMs - now + skewMs
        : 10 * 60_000
    // Clamp: never below the skew window, never an unbounded entry.
    const ttlMs = Math.min(Math.max(horizon, skewMs, 60_000), 24 * 60 * 60_000)
    const recorded = await ctx.methodScratch.put(key, "1", ttlMs)
    if (!recorded.ok) {
      // The dedup store is unavailable — failing open would allow
      // replay. Fail closed.
      return {
        kind: "error",
        error: authError.internalError(
          "saml-sp: could not record assertion ID for replay protection",
        ),
      }
    }
  }

  const authnStatement = extractAuthnStatement(assertionDoc)

  const verified: VerifiedProfile = {
    nameID: profile.nameID,
    nameIDFormat: profile.nameIDFormat ?? "",
    ...(profile.sessionIndex !== undefined
      ? { sessionIndex: profile.sessionIndex }
      : {}),
    ...authnStatement,
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
    ...(idpInitiated && config.idpInitiated
      ? {
          unsolicitedBinding: {
            clientId: config.idpInitiated.defaultClientId,
            redirectUri: config.idpInitiated.defaultRedirectUri,
            scopes: config.idpInitiated.defaultScopes ?? [],
          },
        }
      : {}),
  }
}
