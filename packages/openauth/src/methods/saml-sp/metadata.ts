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
 * `KeyDescriptor` is emitted only when we actually sign AuthnRequests
 * (advertising a cert we cannot use would be the bug);
 * `SingleLogoutService` only when an IdP SLO endpoint is configured
 * and the `/sls` route is therefore served (advertising an endpoint we
 * do not serve would break interop). `AuthnRequestsSigned` /
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
const HTTP_REDIRECT =
  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

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
  /**
   * The SP's own Single Logout Service URL (`/m/<methodId>/sls`).
   * Present ⇒ front-channel SLO is served, so the metadata advertises
   * `SingleLogoutService` for both bindings we accept. Same
   * advertise-only-what-we-serve invariant as the ACS / signing cert.
   */
  slsUrl?: string
  nameIdFormat?: SamlNameIdFormat
  /**
   * SP signing cert (PEM). Present ⇒ we sign AuthnRequests, so the
   * metadata advertises `AuthnRequestsSigned="true"` and a
   * `KeyDescriptor use="signing"`. Keeping this in lockstep with the
   * runtime (the same `config.signingKey.certPem` that actually signs)
   * is the same anti-drift invariant as the entityID/ACS.
   */
  signingCertPem?: string
  /**
   * SP encryption cert (PEM). Present ⇒ the connection accepts
   * encrypted assertions, so the metadata advertises a
   * `KeyDescriptor use="encryption"` (the cert the IdP encrypts to —
   * `config.decryptionKey.certPem`). Same anti-drift / advertise-only-
   * what-we-serve invariant as the signing cert.
   */
  encryptionCertPem?: string
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
  const x509 = (cert: string) =>
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
    certBody(cert) +
    `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
  const keyDescriptor =
    (signed
      ? `\n    <md:KeyDescriptor use="signing">` +
        x509(input.signingCertPem as string) +
        `</md:KeyDescriptor>`
      : "") +
    (input.encryptionCertPem !== undefined
      ? `\n    <md:KeyDescriptor use="encryption">` +
        x509(input.encryptionCertPem) +
        `</md:KeyDescriptor>`
      : "")
  // Schema order: KeyDescriptor → SingleLogoutService → NameIDFormat →
  // AssertionConsumerService. Advertise both bindings we accept at /sls.
  const sls =
    input.slsUrl !== undefined
      ? `\n    <md:SingleLogoutService ` +
        `Binding="${HTTP_REDIRECT}" Location="${xmlEscape(input.slsUrl)}"/>` +
        `\n    <md:SingleLogoutService ` +
        `Binding="${HTTP_POST}" Location="${xmlEscape(input.slsUrl)}"/>`
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
    sls +
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
  // SP SLS URL — same host as the ACS callback, at the public method
  // mount `/m/<methodId>/sls`. Only advertised when SLO is actually
  // served (idp.sloUrl set ⇒ /sls is in publicRoutes). Derived from the
  // same dispatch input as the ACS so it cannot drift.
  const cb = new URL(ctx.dispatch.callbackUrl)
  const slsUrl = `${cb.protocol}//${cb.host}/m/${methodId}/sls`
  const xml = buildSpMetadataXml({
    spEntityId,
    acsUrl: ctx.dispatch.callbackUrl,
    ...(config.idp.sloUrl ? { slsUrl } : {}),
    ...(config.idp.nameIdFormat !== undefined
      ? { nameIdFormat: config.idp.nameIdFormat }
      : {}),
    // Truthful: advertise signing iff we actually sign AuthnRequests.
    ...(config.signAuthnRequest && config.signingKey
      ? { signingCertPem: config.signingKey.certPem }
      : {}),
    // Truthful: advertise an encryption cert iff we accept (and can
    // decrypt) encrypted assertions.
    ...(config.allowEncryptedAssertions && config.decryptionKey
      ? { encryptionCertPem: config.decryptionKey.certPem }
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
