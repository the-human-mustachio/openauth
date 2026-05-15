/**
 * `parseSamlIdpMetadata` — unit coverage.
 *
 * Two real-world metadata shapes (Okta-style with `md:` prefixes and a
 * `use="signing"` KeyDescriptor; Entra-style with no `use` attribute,
 * an SLO endpoint, and a NameIDFormat), plus the malformed-input and
 * wrong-document-type rejections. Namespace-prefix agnosticism is the
 * property under test alongside field extraction.
 */
import { describe, expect, test } from "bun:test"

import { parseSamlIdpMetadata } from "../../../src/methods/saml-sp/parse-idp-metadata"

// A throwaway base64 body (not a real cert) with embedded whitespace —
// the parser must normalise it into a 64-col PEM block.
const CERT_B64 =
  "MIIBdummyBASE64certBODYwithNEWLINES" +
  "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP" +
  "QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ0000111122223333444455556"

const OKTA_STYLE = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="http://www.okta.com/exk1fakeidp">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
            ${CERT_B64.slice(0, 60)}
            ${CERT_B64.slice(60)}
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://corp.okta.com/app/saml/sso/post"/>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://corp.okta.com/app/saml/sso/redirect"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`

const ENTRA_STYLE = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="https://sts.windows.net/tenant-guid/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>${CERT_B64}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://login.microsoftonline.com/tenant-guid/saml2/logout"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://login.microsoftonline.com/tenant-guid/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

describe("parseSamlIdpMetadata", () => {
  test("Okta-style: md: prefixes, use=signing, prefers HTTP-Redirect SSO", () => {
    const r = parseSamlIdpMetadata(OKTA_STYLE)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.entityId).toBe("http://www.okta.com/exk1fakeidp")
    // Two SSO endpoints present; Redirect must win over POST.
    expect(r.value.ssoUrl).toBe("https://corp.okta.com/app/saml/sso/redirect")
    expect(r.value.sloUrl).toBeUndefined()
    expect(r.value.nameIdFormat).toBeUndefined()
    expect(r.value.signingCerts.length).toBe(1)
    const pem = r.value.signingCerts[0]!.pem
    expect(pem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true)
    expect(pem.endsWith("\n-----END CERTIFICATE-----")).toBe(true)
    // Body normalised: all original whitespace stripped, content preserved.
    const body = pem
      .replace("-----BEGIN CERTIFICATE-----\n", "")
      .replace("\n-----END CERTIFICATE-----", "")
      .replace(/\n/g, "")
    expect(body).toBe(CERT_B64)
    // Re-chunked to 64-col lines.
    for (const line of pem.split("\n").slice(1, -1)) {
      expect(line.length).toBeLessThanOrEqual(64)
    }
  })

  test("Entra-style: default ns, no use attr, captures SLO + NameIDFormat", () => {
    const r = parseSamlIdpMetadata(ENTRA_STYLE)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.entityId).toBe("https://sts.windows.net/tenant-guid/")
    expect(r.value.ssoUrl).toBe(
      "https://login.microsoftonline.com/tenant-guid/saml2",
    )
    expect(r.value.sloUrl).toBe(
      "https://login.microsoftonline.com/tenant-guid/saml2/logout",
    )
    expect(r.value.nameIdFormat).toBe("persistent")
    expect(r.value.signingCerts.length).toBe(1)
  })

  test("rejects malformed XML", () => {
    const r = parseSamlIdpMetadata("<EntityDescriptor><oops")
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.code).toBe("invalid_request")
  })

  test("rejects empty input", () => {
    const r = parseSamlIdpMetadata("   ")
    expect(r.ok).toBe(false)
  })

  test("rejects SP metadata (no IDPSSODescriptor)", () => {
    const sp = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
      entityID="https://sp.example/meta">
      <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService
          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          Location="https://sp.example/acs" index="0"/>
      </SPSSODescriptor>
    </EntityDescriptor>`
    const r = parseSamlIdpMetadata(sp)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.description).toContain("IDPSSODescriptor")
  })

  test("rejects IdP metadata with no signing certificate", () => {
    const noCert = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
      entityID="https://idp.example/meta">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService
          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          Location="https://idp.example/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>`
    const r = parseSamlIdpMetadata(noCert)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.description).toContain("X509Certificate")
  })

  test("rejects EntityDescriptor without entityID", () => {
    const noId = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>${CERT_B64}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
        <SingleSignOnService
          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          Location="https://idp.example/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>`
    const r = parseSamlIdpMetadata(noId)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.description).toContain("entityID")
  })
})
