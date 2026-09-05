/**
 * SAML Response fixture builder.
 *
 * Signs with node-saml's OWN `signSamlPost` primitive (deep import —
 * the package ships no `exports` map so this is resolvable). Signing
 * and verifying with the same library guarantees the only thing a
 * fixture exercises is the property under test, not an incidental
 * canonicalization mismatch.
 *
 * Attack knobs each isolate one gauntlet item. Unless a knob says
 * otherwise the produced Response is valid and node-saml accepts it.
 */
// Deep import — node-saml ships no `exports` map, so `lib/*` is
// resolvable and carries co-located .d.ts. Test-only.
import { signSamlPost } from "@node-saml/node-saml/lib/saml-post-signing"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const F = (n: string) =>
  readFileSync(join(import.meta.dir, n), "utf8")

export const IDP_CERT = F("idp-cert.pem")
const IDP_KEY = F("idp-key.pem")
const ATTACKER_CERT = F("attacker-cert.pem")
const ATTACKER_KEY = F("attacker-key.pem")

export type BuildOpts = {
  requestId: string
  spEntityId: string
  acsUrl: string
  idpEntityId: string
  nameId?: string
  attributes?: Record<string, string | string[]>
  // attack knobs
  unsigned?: boolean
  wrongKey?: boolean
  badAudience?: boolean
  badRecipient?: boolean
  /** Omit the `Recipient` attribute entirely (still signed + valid otherwise). */
  noRecipient?: boolean
  /** Unsolicited / IdP-initiated: omit InResponseTo (no prior AuthnRequest). */
  unsolicited?: boolean
  /** Emit `AuthnStatement/@SessionNotOnOrAfter` (Unix ms). Omitted by default. */
  sessionNotOnOrAfter?: number
  /** Override the asserted `AuthnContextClassRef`. */
  authnContextClassRef?: string
  /**
   * Sign the outer `<samlp:Response>` instead of the `<saml:Assertion>`
   * — the shape emitted by IdPs that sign only at the Response level.
   */
  signResponseInstead?: boolean
  expired?: boolean
  xsw?: boolean
  xxe?: boolean
}

const iso = (ms: number) => new Date(ms).toISOString()

function attributeXml(attrs: Record<string, string | string[]>): string {
  const out: string[] = []
  for (const [name, val] of Object.entries(attrs)) {
    const vals = Array.isArray(val) ? val : [val]
    out.push(
      `<saml:Attribute Name="${name}">` +
        vals
          .map(
            (v) =>
              `<saml:AttributeValue>${v}</saml:AttributeValue>`,
          )
          .join("") +
        `</saml:Attribute>`,
    )
  }
  return out.length
    ? `<saml:AttributeStatement>${out.join("")}</saml:AttributeStatement>`
    : ""
}

export function buildSamlResponse(opts: BuildOpts): string {
  const now = Date.now()
  const notBefore = iso(now - 60_000)
  // Well outside the 60s accepted clock skew so "expired" is
  // unambiguous (node-saml: now - skew >= NotOnOrAfter ⇒ expired).
  const notOnOrAfter = opts.expired
    ? iso(now - 10 * 60_000)
    : iso(now + 5 * 60_000)
  const audience = opts.badAudience
    ? "https://wrong-sp.example/metadata"
    : opts.spEntityId
  const recipient = opts.badRecipient
    ? "https://wrong-sp.example/acs"
    : opts.acsUrl
  // For the XXE case the entity reference goes into the NameID *before*
  // signing, so it is part of the signed document — a real attempt to
  // get the parser to expand an external entity into the subject.
  const nameId = opts.xxe ? "&xxe;" : (opts.nameId ?? "user-persistent-id-001")
  const assertionId = "_assertion_" + Math.random().toString(36).slice(2)
  const responseId = "_response_" + Math.random().toString(36).slice(2)

  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${assertionId}" Version="2.0" IssueInstant="${iso(now)}">` +
    `<saml:Issuer>${opts.idpEntityId}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData ` +
    (opts.unsolicited ? "" : `InResponseTo="${opts.requestId}" `) +
    (opts.noRecipient ? "" : `Recipient="${recipient}" `) +
    `NotOnOrAfter="${notOnOrAfter}"/>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience>` +
    `</saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="sess-1"` +
    (opts.sessionNotOnOrAfter !== undefined
      ? ` SessionNotOnOrAfter="${iso(opts.sessionNotOnOrAfter)}"`
      : "") +
    `>` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>` +
    (opts.authnContextClassRef ??
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport") +
    `</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    attributeXml(opts.attributes ?? {}) +
    `</saml:Assertion>`

  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${responseId}" Version="2.0" IssueInstant="${iso(now)}" ` +
    `Destination="${opts.acsUrl}"` +
    (opts.unsolicited ? "" : ` InResponseTo="${opts.requestId}"`) +
    `>` +
    `<saml:Issuer>${opts.idpEntityId}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode ` +
    `Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertion +
    `</samlp:Response>`

  let xml = response
  if (!opts.unsigned) {
    const assertionXPath = opts.signResponseInstead
      ? '/*[local-name(.)="Response"]'
      : '/*[local-name(.)="Response"]/*[local-name(.)="Assertion"]'
    xml = signSamlPost(response, assertionXPath, {
      privateKey: opts.wrongKey ? ATTACKER_KEY : IDP_KEY,
      publicCert: opts.wrongKey ? ATTACKER_CERT : IDP_CERT,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    })
  }

  if (opts.xsw) {
    // Signature-wrapping: duplicate the (signed) assertion and give the
    // forged copy the original signed ID while mutating its NameID.
    // node-saml must reject — only the signed bytes may be trusted and
    // exactly one element may carry the signed ID.
    const m = xml.match(/<saml:Assertion[\s\S]*?<\/saml:Assertion>/)
    if (m) {
      const forged = m[0].replace(
        />[^<]*</,
        ">attacker-controlled-subject<",
      )
      xml = xml.replace(m[0], forged + m[0])
    }
  }

  if (opts.xxe) {
    // Prepend a DOCTYPE declaring an external SYSTEM entity. The signed
    // NameID contains `&xxe;`. A vulnerable parser would expand it to
    // the file's contents; @xmldom/xmldom must not.
    xml =
      `<?xml version="1.0"?>\n` +
      `<!DOCTYPE samlp:Response [ ` +
      `<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n` +
      xml.replace(/^<\?xml[^>]*\?>\s*/, "")
  }

  return Buffer.from(xml, "utf8").toString("base64")
}
