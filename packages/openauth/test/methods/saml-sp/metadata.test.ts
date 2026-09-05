/**
 * SP metadata — pure builder, dispatch behaviour, and the
 * **anti-drift** guard: the published entityID / ACS must equal what
 * the live AuthnRequest path derives for the same
 * (issuer, tenant, methodId). If those ever diverge an IdP import
 * silently breaks with opaque audience/recipient errors, so this is the
 * load-bearing test for metadata correctness.
 */
import { describe, expect, test } from "bun:test"
import { inflateRawSync } from "node:zlib"

import xmldom from "@xmldom/xmldom"

import { MemorySessionStore } from "../../../src/adapters/memory"
import { dispatchMethod } from "../../../src/domain/method-dispatch"
import { samlSpFactory } from "../../../src/methods/saml-sp/factory"
import { buildSpMetadataXml } from "../../../src/methods/saml-sp/metadata"
import { parseSamlIdpMetadata } from "../../../src/methods/saml-sp/parse-idp-metadata"

const { DOMParser } = xmldom
import type { SamlSpConfig } from "../../../src/methods/saml-sp/types"
import type { AnyAuthMethodFactory } from "../../../src/types/method"
import { asTenantId, type TenantContext } from "../../../src/types/tenant"

import { buildTenant } from "../../helpers/tenant"
import { makeFlow } from "../../ports/fixtures"
import { IDP_CERT } from "./fixtures/build-response"

const ISSUER_URL = "https://idp.example"
const TENANT = "acme"
const METHOD_ID = "corp-saml"
const IDP_ENTITY = "https://corp-idp.example/saml/metadata"

function config(
  nameIdFormat?: SamlSpConfig["idp"]["nameIdFormat"],
): SamlSpConfig {
  return {
    idp: {
      entityId: IDP_ENTITY,
      ssoUrl: "https://corp-idp.example/sso",
      ...(nameIdFormat !== undefined ? { nameIdFormat } : {}),
      signingCerts: [{ pem: IDP_CERT }],
    },
    attributeMapping: { subject: { source: "nameId" } },
  }
}

async function buildMethod(cfg: SamlSpConfig) {
  const factory: AnyAuthMethodFactory = samlSpFactory
  return factory.build({
    id: METHOD_ID,
    kind: "saml-sp",
    tenantId: asTenantId(TENANT),
    config: cfg,
  })
}

async function tenantCtx(): Promise<TenantContext> {
  return {
    id: asTenantId(TENANT),
    config: await buildTenant({ id: TENANT }),
    request: {
      raw: new Request(`${ISSUER_URL}/m/${METHOD_ID}/metadata`),
      custom: {},
    },
  }
}

const DISPATCH = {
  state: "",
  callbackUrl: `${ISSUER_URL}/cb/${METHOD_ID}`,
  issuerUrl: ISSUER_URL,
}

describe("buildSpMetadataXml (pure)", () => {
  test("emits a conformant SPSSODescriptor with HTTP-POST ACS", () => {
    const xml = buildSpMetadataXml({
      spEntityId: "https://idp.example/acme/corp-saml",
      acsUrl: "https://idp.example/cb/corp-saml",
    })
    expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>')
    expect(xml).toContain('entityID="https://idp.example/acme/corp-saml"')
    expect(xml).toContain(
      'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"',
    )
    expect(xml).toContain('AuthnRequestsSigned="false"')
    expect(xml).toContain('WantAssertionsSigned="true"')
    expect(xml).toContain(
      'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"',
    )
    expect(xml).toContain('Location="https://idp.example/cb/corp-saml"')
    expect(xml).toContain('index="0"')
    expect(xml).toContain('isDefault="true"')
    // v1 deliberately advertises neither a cert nor an SLO endpoint.
    expect(xml).not.toContain("KeyDescriptor")
    expect(xml).not.toContain("SingleLogoutService")
  })

  test("NameIDFormat present iff configured", () => {
    expect(buildSpMetadataXml({ spEntityId: "e", acsUrl: "a" })).not.toContain(
      "NameIDFormat",
    )
    expect(
      buildSpMetadataXml({
        spEntityId: "e",
        acsUrl: "a",
        nameIdFormat: "persistent",
      }),
    ).toContain(
      "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>",
    )
  })

  test('XML-escapes &, <, >, " in values', () => {
    const xml = buildSpMetadataXml({
      spEntityId: 'https://idp.example/t?a=1&b=<2>"x"',
      acsUrl: "https://idp.example/cb?x=1&y=2",
    })
    expect(xml).toContain("a=1&amp;b=&lt;2&gt;&quot;x&quot;")
    expect(xml).toContain("x=1&amp;y=2")
    // Must still be well-formed after escaping.
    const doc = new DOMParser().parseFromString(
      xml,
      "text/xml",
    ) as unknown as Document
    expect(doc.documentElement?.localName).toBe("EntityDescriptor")
  })

  test("DOM structure: one ACS, no KeyDescriptor, no SLO, well-formed", () => {
    const xml = buildSpMetadataXml({
      spEntityId: "https://idp.example/acme/corp-saml",
      acsUrl: "https://idp.example/cb/corp-saml",
      nameIdFormat: "emailAddress",
    })
    const doc = new DOMParser().parseFromString(
      xml,
      "text/xml",
    ) as unknown as Document
    expect(doc.documentElement?.localName).toBe("EntityDescriptor")
    const acs = doc.getElementsByTagNameNS("*", "AssertionConsumerService")
    expect(acs.length).toBe(1)
    expect(acs[0]?.getAttribute("Binding")).toBe(
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    )
    expect(acs[0]?.getAttribute("index")).toBe("0")
    expect(doc.getElementsByTagNameNS("*", "KeyDescriptor").length).toBe(0)
    expect(doc.getElementsByTagNameNS("*", "SingleLogoutService").length).toBe(
      0,
    )
    expect(doc.getElementsByTagNameNS("*", "SPSSODescriptor").length).toBe(1)
    expect(doc.getElementsByTagNameNS("*", "IDPSSODescriptor").length).toBe(0)
  })

  test("signing configured → AuthnRequestsSigned=true + signing KeyDescriptor", () => {
    const xml = buildSpMetadataXml({
      spEntityId: "https://idp.example/acme/corp-saml",
      acsUrl: "https://idp.example/cb/corp-saml",
      signingCertPem:
        "-----BEGIN CERTIFICATE-----\nQUJDREVG\nR0hJSktM\n-----END CERTIFICATE-----",
    })
    expect(xml).toContain('AuthnRequestsSigned="true"')
    const doc = new DOMParser().parseFromString(
      xml,
      "text/xml",
    ) as unknown as Document
    const kd = doc.getElementsByTagNameNS("*", "KeyDescriptor")
    expect(kd.length).toBe(1)
    expect(kd[0]?.getAttribute("use")).toBe("signing")
    const cert = doc.getElementsByTagNameNS("*", "X509Certificate")
    expect(cert.length).toBe(1)
    // PEM headers + whitespace stripped to a bare base64 body.
    expect(cert[0]?.textContent).toBe("QUJDREVGR0hJSktM")
    expect(doc.documentElement?.localName).toBe("EntityDescriptor")
  })

  test("cross-check: parseSamlIdpMetadata rejects our SP metadata", () => {
    // Inbound (parse IdP) and outbound (emit SP) are distinct shapes —
    // feeding our SP doc to the IdP parser must fail (no IDPSSODescriptor),
    // proving the two directions can't be silently confused.
    const sp = buildSpMetadataXml({
      spEntityId: "https://idp.example/acme/corp-saml",
      acsUrl: "https://idp.example/cb/corp-saml",
    })
    const parsed = parseSamlIdpMetadata(sp)
    expect(parsed.ok).toBe(false)
    if (parsed.ok) return
    expect(parsed.error.description).toContain("IDPSSODescriptor")
  })
})

describe("GET /metadata route", () => {
  test("dispatch returns a cached samlmetadata+xml challenge", async () => {
    const method = await buildMethod(config())
    const res = await dispatchMethod({
      method,
      route: "GET /metadata",
      tenant: await tenantCtx(),
      request: new Request(`${ISSUER_URL}/m/${METHOD_ID}/metadata`),
      subPath: "/metadata",
      flow: null,
      cookies: new Map(),
      sessionStore: new MemorySessionStore(),
      dispatch: DISPATCH,
    })
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("challenge")
    if (res.value.kind !== "challenge") return
    expect(res.value.response.status).toBe(200)
    expect(res.value.response.headers.get("content-type")).toBe(
      "application/samlmetadata+xml",
    )
    expect(res.value.cache).toEqual({ sMaxAge: 300 })
    const body = await res.value.response.text()
    expect(body).toContain("<md:EntityDescriptor")
  })

  test("ANTI-DRIFT: metadata entityID + ACS == what GET /authorize derives", async () => {
    const method = await buildMethod(config())
    const tenant = await tenantCtx()
    const store = new MemorySessionStore()

    // Drive the live SP-initiated path and read the SP binding it
    // committed to methodState (the exact values the IdP will see /
    // validate at the ACS).
    const flow = makeFlow({
      flowId: "drift-flow",
      tenantId: asTenantId(TENANT),
      methodId: METHOD_ID,
      methodKind: "saml-sp",
      callbackPath: `/cb/${METHOD_ID}`,
    })
    await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)
    const authz = await dispatchMethod({
      method,
      route: "GET /authorize",
      tenant,
      request: new Request(`${ISSUER_URL}/authorize`),
      subPath: "/authorize",
      flow,
      cookies: new Map(),
      sessionStore: store,
      dispatch: { ...DISPATCH, state: "state.envelope" },
    })
    expect(authz.ok).toBe(true)
    if (!authz.ok || authz.value.kind !== "challenge") return
    const updated = await store.readFlow(flow.flowId)
    if (!updated.ok) return
    const st = updated.value.methodState as {
      spEntityId: string
      acsUrl: string
    }
    // Sanity: the AuthnRequest XML's Issuer is that same SP entityID.
    const loc = authz.value.response.headers.get("location") as string
    const sr = new URL(loc).searchParams.get("SAMLRequest") as string
    const reqXml = inflateRawSync(Buffer.from(sr, "base64")).toString("utf8")
    expect(reqXml).toContain(`>${st.spEntityId}</saml:Issuer>`)

    // Now the metadata, same dispatch inputs.
    const meta = await dispatchMethod({
      method,
      route: "GET /metadata",
      tenant,
      request: new Request(`${ISSUER_URL}/m/${METHOD_ID}/metadata`),
      subPath: "/metadata",
      flow: null,
      cookies: new Map(),
      sessionStore: store,
      dispatch: DISPATCH,
    })
    if (!meta.ok || meta.value.kind !== "challenge") return
    const xml = await meta.value.response.text()

    // The published identifiers MUST equal the runtime ones.
    expect(xml).toContain(`entityID="${st.spEntityId}"`)
    expect(xml).toContain(`Location="${st.acsUrl}"`)
  })

  test("ANTI-DRIFT: an spEntityId override reaches metadata too", async () => {
    // The override exists so a customer can keep an entityID already
    // registered at their IdP. If it reached the AuthnRequest but not
    // the metadata, an IdP import would silently configure the wrong
    // audience — exactly the drift this suite exists to prevent.
    const OVERRIDE = "https://legacy-sp.example/saml/sp"
    const method = await buildMethod({ ...config(), spEntityId: OVERRIDE })
    const tenant = await tenantCtx()
    const store = new MemorySessionStore()

    const meta = await dispatchMethod({
      method,
      route: "GET /metadata",
      tenant,
      request: new Request(`${ISSUER_URL}/m/${METHOD_ID}/metadata`),
      subPath: "/metadata",
      flow: null,
      cookies: new Map(),
      sessionStore: store,
      dispatch: DISPATCH,
    })
    expect(meta.ok).toBe(true)
    if (!meta.ok || meta.value.kind !== "challenge") return
    const xml = await meta.value.response.text()
    expect(xml).toContain(`entityID="${OVERRIDE}"`)
    expect(xml).not.toContain(`entityID="${ISSUER_URL}/${TENANT}/${METHOD_ID}"`)
  })

  test("WantAssertionsSigned states actual behaviour, not a constant", async () => {
    const tenant = await tenantCtx()
    const store = new MemorySessionStore()

    const render = async (cfg: SamlSpConfig) => {
      const res = await dispatchMethod({
        method: await buildMethod(cfg),
        route: "GET /metadata",
        tenant,
        request: new Request(`${ISSUER_URL}/m/${METHOD_ID}/metadata`),
        subPath: "/metadata",
        flow: null,
        cookies: new Map(),
        sessionStore: store,
        dispatch: DISPATCH,
      })
      if (!res.ok || res.value.kind !== "challenge") throw new Error("no xml")
      return res.value.response.text()
    }

    expect(await render(config())).toContain('WantAssertionsSigned="true"')
    expect(
      await render({
        ...config(),
        requireSignedAssertion: false,
        requireSignedResponse: true,
      }),
    ).toContain('WantAssertionsSigned="false"')
  })
})
