/**
 * SP metadata XML — the outbound half of metadata exchange
 * (`parseSamlIdpMetadata` is the inbound half).
 *
 * Served anonymously at `GET /m/<methodId>/metadata` via the method's
 * `publicRoutes` allowlist (no flow cookie). An enterprise IdP admin
 * imports this document to register us as an SP.
 *
 * **Conformance invariant:** the `entityID` and ACS `Location` are
 * derived from the *same* inputs the live AuthnRequest / ACS path uses
 * (`deriveSpEntityId(issuerUrl, tenantId, methodId)` and
 * `ctx.dispatch.callbackUrl`). The metadata therefore describes exactly
 * what the runtime accepts — never an independently re-specified value
 * that could drift. `metadata.test.ts` asserts this equality against
 * `buildAuthnRequestRedirect` so drift fails CI.
 *
 * v1 omits `KeyDescriptor` (we neither sign AuthnRequests nor accept
 * encrypted assertions yet — advertising a cert we cannot use would be
 * the bug) and `SingleLogoutService` (SLO is a later phase —
 * advertising an endpoint we do not serve would break interop). Both
 * are standards-valid omissions; `AuthnRequestsSigned="false"` /
 * `WantAssertionsSigned="true"` truthfully state actual behaviour.
 */
import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"

import { deriveSpEntityId } from "./saml-instance"
import type {
  SamlNameIdFormat,
  SamlSpConfig,
  SamlSpProperties,
  SamlSpState,
} from "./types"

const NAME_ID_FORMAT_URN: Record<SamlNameIdFormat, string> = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
}

const HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

/** Minimal XML attribute/text escaping for URL-shaped values. */
function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
}

export type SpMetadataInput = {
  spEntityId: string
  acsUrl: string
  nameIdFormat?: SamlNameIdFormat
  /**
   * SP signing cert (PEM). Present ⇒ we sign AuthnRequests, so the
   * metadata advertises `AuthnRequestsSigned="true"` and a
   * `KeyDescriptor use="signing"`. Keeping this in lockstep with the
   * runtime (the same `config.signingKey.certPem` that actually signs)
   * is the same anti-drift invariant as the entityID/ACS.
   */
  signingCertPem?: string
}

/** PEM cert body → bare base64 (SAML metadata X509Certificate form). */
function certBody(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "")
}

/**
 * Pure SP metadata builder. Mirrors `parseSamlIdpMetadata`'s purity so
 * it is trivially unit-testable and reusable.
 */
export function buildSpMetadataXml(input: SpMetadataInput): string {
  const entityId = xmlEscape(input.spEntityId)
  const acs = xmlEscape(input.acsUrl)
  const signed = input.signingCertPem !== undefined
  const nameIdLine =
    input.nameIdFormat !== undefined
      ? `\n    <md:NameIDFormat>${NAME_ID_FORMAT_URN[input.nameIdFormat]}</md:NameIDFormat>`
      : ""
  const keyDescriptor = signed
    ? `\n    <md:KeyDescriptor use="signing">` +
      `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
      certBody(input.signingCertPem as string) +
      `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
      `</md:KeyDescriptor>`
    : ""

  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ` +
    `xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ` +
    `entityID="${entityId}">\n` +
    `  <md:SPSSODescriptor AuthnRequestsSigned="${signed}" ` +
    `WantAssertionsSigned="true" ` +
    `protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
    keyDescriptor +
    nameIdLine +
    `\n    <md:AssertionConsumerService ` +
    `Binding="${HTTP_POST}" Location="${acs}" index="0" isDefault="true"/>` +
    `\n  </md:SPSSODescriptor>\n` +
    `</md:EntityDescriptor>\n`
  )
}

/**
 * `GET /metadata` route handler. Anonymous (declared in the method's
 * `publicRoutes`): `ctx.flow` / `ctx.methodState` are null; everything
 * comes from `ctx.tenant` + `ctx.dispatch` + captured config.
 */
export async function buildSpMetadata(
  ctx: MethodContext<SamlSpState>,
  methodId: string,
  config: SamlSpConfig,
): Promise<MethodResult<SamlSpProperties, SamlSpState>> {
  if (!ctx.dispatch) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: metadata route dispatched without issuer context " +
          "(ctx.dispatch is null)",
      ),
    }
  }

  const spEntityId = deriveSpEntityId(
    ctx.dispatch.issuerUrl,
    ctx.tenant.id,
    methodId,
  )
  const xml = buildSpMetadataXml({
    spEntityId,
    acsUrl: ctx.dispatch.callbackUrl,
    ...(config.idp.nameIdFormat !== undefined
      ? { nameIdFormat: config.idp.nameIdFormat }
      : {}),
    // Truthful: advertise signing iff we actually sign AuthnRequests.
    ...(config.signAuthnRequest && config.signingKey
      ? { signingCertPem: config.signingKey.certPem }
      : {}),
  })

  return {
    kind: "challenge",
    response: new Response(xml, {
      status: 200,
      headers: { "content-type": "application/samlmetadata+xml" },
    }),
    cache: { sMaxAge: 300 },
  }
}
