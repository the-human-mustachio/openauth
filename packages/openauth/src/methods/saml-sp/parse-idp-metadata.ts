/**
 * `parseSamlIdpMetadata` — turn an IdP's SAML 2.0 metadata XML into the
 * `SamlIdpConfig` shape a host stores per method instance.
 *
 * This is a **pure** helper exposed so a host console can offer "paste
 * the IdP metadata XML / URL" instead of making operators hand-copy
 * entityID, SSO URL, and signing certs. It does not import node-saml —
 * metadata parsing needs no signature verification (the document is
 * fetched from a trusted admin, and every assertion is independently
 * verified at the ACS regardless of what the metadata claimed).
 *
 * Namespace-agnostic: elements are matched by local name so prefixes
 * (`md:`, `ds:`, none) don't matter. Returns `Result` rather than
 * throwing, matching the library's domain convention.
 */
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

// CJS interop per the SAML house-style note.
import xmldom from "@xmldom/xmldom"

import type { SamlIdpConfig, SamlNameIdFormat } from "./types"

const { DOMParser } = xmldom

const HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
const HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

const NAME_ID_FORMAT_BY_URN: Record<string, SamlNameIdFormat> = {
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent": "persistent",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient": "transient",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": "emailAddress",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified": "unspecified",
}

function els(root: Document | Element, localName: string): Element[] {
  const list = root.getElementsByTagNameNS("*", localName)
  const out: Element[] = []
  for (let i = 0; i < list.length; i++) {
    const n = list[i]
    if (n) out.push(n)
  }
  return out
}

/** Pick an endpoint by binding preference (Redirect → POST → first). */
function pickEndpoint(endpoints: Element[]): string | undefined {
  if (endpoints.length === 0) return undefined
  const byBinding = (b: string) =>
    endpoints.find((e) => e.getAttribute("Binding") === b)
  const chosen =
    byBinding(HTTP_REDIRECT) ?? byBinding(HTTP_POST) ?? endpoints[0]
  const loc = chosen?.getAttribute("Location")
  return loc && loc.length > 0 ? loc : undefined
}

/** Normalise a base64 cert body into a PEM block (64-col lines). */
function toPem(rawX509: string): string {
  const b64 = rawX509.replace(/\s+/g, "")
  const lines = b64.match(/.{1,64}/g) ?? [b64]
  return (
    "-----BEGIN CERTIFICATE-----\n" +
    lines.join("\n") +
    "\n-----END CERTIFICATE-----"
  )
}

export function parseSamlIdpMetadata(xml: string): Result<SamlIdpConfig> {
  if (typeof xml !== "string" || xml.trim().length === 0) {
    return err(authError.invalidRequest("metadata XML is empty"))
  }

  let doc: Document
  try {
    doc = new DOMParser().parseFromString(
      xml,
      "text/xml",
    ) as unknown as Document
  } catch (e) {
    return err(
      authError.invalidRequest(
        `metadata XML is not well-formed: ${
          e instanceof Error ? e.message : String(e)
        }`,
      ),
    )
  }
  if (!doc?.documentElement) {
    return err(authError.invalidRequest("metadata XML has no root element"))
  }

  const entityDescriptor = els(doc, "EntityDescriptor")[0]
  if (!entityDescriptor) {
    return err(authError.invalidRequest("metadata has no <EntityDescriptor>"))
  }
  const entityId = entityDescriptor.getAttribute("entityID")
  if (!entityId) {
    return err(authError.invalidRequest("EntityDescriptor has no entityID"))
  }

  const idp = els(entityDescriptor, "IDPSSODescriptor")[0]
  if (!idp) {
    return err(
      authError.invalidRequest(
        "not an IdP metadata document (no <IDPSSODescriptor>) — this looks " +
          "like SP metadata",
      ),
    )
  }

  const ssoUrl = pickEndpoint(els(idp, "SingleSignOnService"))
  if (!ssoUrl) {
    return err(
      authError.invalidRequest(
        "IDPSSODescriptor has no usable <SingleSignOnService> Location",
      ),
    )
  }
  const sloUrl = pickEndpoint(els(idp, "SingleLogoutService"))

  let nameIdFormat: SamlNameIdFormat | undefined
  for (const f of els(idp, "NameIDFormat")) {
    const mapped = NAME_ID_FORMAT_BY_URN[(f.textContent ?? "").trim()]
    if (mapped) {
      nameIdFormat = mapped
      break
    }
  }

  // Signing certs: a KeyDescriptor with use="signing", or with no `use`
  // (per SAML metadata spec an absent `use` means the key is valid for
  // both signing and encryption).
  const signingCerts: { pem: string }[] = []
  for (const kd of els(idp, "KeyDescriptor")) {
    const use = kd.getAttribute("use")
    if (use && use !== "signing") continue
    for (const cert of els(kd, "X509Certificate")) {
      const body = (cert.textContent ?? "").trim()
      if (body.length > 0) signingCerts.push({ pem: toPem(body) })
    }
  }
  if (signingCerts.length === 0) {
    return err(
      authError.invalidRequest(
        "IDPSSODescriptor has no signing <X509Certificate>",
      ),
    )
  }

  return ok({
    entityId,
    ssoUrl,
    ...(sloUrl !== undefined ? { sloUrl } : {}),
    ...(nameIdFormat !== undefined ? { nameIdFormat } : {}),
    signingCerts,
  })
}
