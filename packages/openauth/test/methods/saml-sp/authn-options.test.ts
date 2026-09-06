/**
 * AuthnRequest options + AuthnStatement surfacing.
 *
 * Covers the knobs that decide what we *ask* the IdP for
 * (`RequestedAuthnContext`, `ForceAuthn`), the SP entityID override,
 * the signature-posture knobs, and the `AuthnStatement` facts we hand
 * back to the host.
 *
 * The `RequestedAuthnContext` default is the load-bearing one: node-saml
 * defaults to demanding `PasswordProtectedTransport` with
 * `Comparison="exact"`, which an IdP running an MFA policy can answer
 * with `NoAuthnContext` instead of a login. We invert that default, and
 * the first test here is what keeps it inverted.
 */
import { describe, expect, test } from "bun:test"
import { inflateRawSync } from "node:zlib"

import { MemorySessionStore } from "../../../src/adapters/memory"
import { dispatchMethod } from "../../../src/domain/method-dispatch"
import { samlSpFactory } from "../../../src/methods/saml-sp/factory"
import type {
  SamlSpConfig,
  SamlSpProperties,
} from "../../../src/methods/saml-sp/types"
import type { AnyAuthMethodFactory } from "../../../src/types/method"
import { asTenantId, type TenantContext } from "../../../src/types/tenant"

import { buildTenant } from "../../helpers/tenant"
import { makeFlow } from "../../ports/fixtures"
import { buildSamlResponse, IDP_CERT } from "./fixtures/build-response"

const ISSUER_URL = "https://idp.example"
const TENANT = "acme"
const METHOD_ID = "corp-saml"
const IDP_ENTITY = "https://corp-idp.example/saml/metadata"
const STATE_ENVELOPE = "state.envelope.mac"

const MFA_CLASS = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthn"

function config(over: Partial<SamlSpConfig> = {}): SamlSpConfig {
  return {
    idp: {
      entityId: IDP_ENTITY,
      ssoUrl: "https://corp-idp.example/sso",
      nameIdFormat: "persistent",
      signingCerts: [{ pem: IDP_CERT }],
    },
    attributeMapping: { subject: { source: "nameId" } },
    ...over,
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
    request: { raw: new Request(`${ISSUER_URL}/authorize`), custom: {} },
  }
}

/** Run `GET /authorize` and return the decoded AuthnRequest XML + binding. */
async function authnRequestXml(cfg: SamlSpConfig) {
  const store = new MemorySessionStore()
  const method = await buildMethod(cfg)
  const tenant = await tenantCtx()
  const flow = makeFlow({
    flowId: "saml-flow-1",
    tenantId: asTenantId(TENANT),
    methodId: METHOD_ID,
    methodKind: "saml-sp",
    callbackPath: `/cb/${METHOD_ID}`,
  })
  await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)

  const res = await dispatchMethod({
    method,
    route: "GET /authorize",
    tenant,
    request: tenant.request.raw,
    subPath: "/authorize",
    flow,
    cookies: new Map(),
    sessionStore: store,
    issuerUrl: ISSUER_URL,
    dispatch: {
      state: STATE_ENVELOPE,
      callbackUrl: `${ISSUER_URL}/cb/${METHOD_ID}`,
      issuerUrl: ISSUER_URL,
    },
  })
  if (!res.ok || res.value.kind !== "challenge") {
    throw new Error("AuthnRequest dispatch failed")
  }
  const loc = res.value.response.headers.get("location") as string
  const samlRequest = new URL(loc).searchParams.get("SAMLRequest") as string
  const xml = inflateRawSync(Buffer.from(samlRequest, "base64")).toString(
    "utf8",
  )
  const stored = await store.readFlow(flow.flowId)
  if (!stored.ok) throw new Error("flow vanished")
  const st = stored.value.methodState as {
    spEntityId: string
    acsUrl: string
  }
  return {
    xml,
    requestId: /\sID="([^"]+)"/.exec(xml)?.[1] as string,
    store,
    method,
    tenant,
    flow: stored.value,
    ...st,
  }
}

async function postAssertion(
  primed: Awaited<ReturnType<typeof authnRequestXml>>,
  samlResponseB64: string,
) {
  const body = new URLSearchParams({
    SAMLResponse: samlResponseB64,
    RelayState: STATE_ENVELOPE,
  }).toString()
  return dispatchMethod({
    method: primed.method,
    route: "GET /callback",
    tenant: primed.tenant,
    request: new Request(`${ISSUER_URL}/cb/${METHOD_ID}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }),
    subPath: "/callback",
    flow: primed.flow,
    cookies: new Map(),
    sessionStore: primed.store,
    issuerUrl: ISSUER_URL,
    dispatch: null,
  })
}

describe("SAML SP — RequestedAuthnContext", () => {
  test("default: no RequestedAuthnContext element is sent at all", async () => {
    const { xml } = await authnRequestXml(config())
    // node-saml's own default would put PasswordProtectedTransport +
    // Comparison="exact" here. Demanding an exact context an MFA-enabled
    // IdP cannot match is answered with NoAuthnContext, not a login.
    expect(xml).not.toContain("RequestedAuthnContext")
    expect(xml).not.toContain("PasswordProtectedTransport")
  })

  test("configured: class refs are requested with the given comparison", async () => {
    const { xml } = await authnRequestXml(
      config({
        requestedAuthnContext: {
          classRefs: [MFA_CLASS],
          comparison: "minimum",
        },
      }),
    )
    expect(xml).toContain("RequestedAuthnContext")
    expect(xml).toContain(MFA_CLASS)
    expect(xml).toContain('Comparison="minimum"')
  })

  test("comparison defaults to exact when class refs are given", async () => {
    const { xml } = await authnRequestXml(
      config({ requestedAuthnContext: { classRefs: [MFA_CLASS] } }),
    )
    expect(xml).toContain('Comparison="exact"')
  })
})

describe("SAML SP — ForceAuthn", () => {
  test("absent by default", async () => {
    const { xml } = await authnRequestXml(config())
    expect(xml).not.toContain("ForceAuthn")
  })

  test("forceAuthn: true → ForceAuthn on the AuthnRequest", async () => {
    const { xml } = await authnRequestXml(config({ forceAuthn: true }))
    expect(xml).toContain('ForceAuthn="true"')
  })
})

describe("SAML SP — spEntityId override", () => {
  const OVERRIDE = "https://legacy-sp.example/saml/sp"

  test("derived by default", async () => {
    const primed = await authnRequestXml(config())
    expect(primed.spEntityId).toBe(`${ISSUER_URL}/${TENANT}/${METHOD_ID}`)
  })

  test("override drives the AuthnRequest Issuer and the committed binding", async () => {
    const primed = await authnRequestXml(config({ spEntityId: OVERRIDE }))
    expect(primed.spEntityId).toBe(OVERRIDE)
    expect(primed.xml).toContain(OVERRIDE)
  })

  test("override end-to-end: an assertion audienced to it is accepted", async () => {
    const cfg = config({ spEntityId: OVERRIDE })
    const primed = await authnRequestXml(cfg)
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: OVERRIDE,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("success")
  })

  test("override end-to-end: the old derived audience is now rejected", async () => {
    const cfg = config({ spEntityId: OVERRIDE })
    const primed = await authnRequestXml(cfg)
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      // Audienced to the derived entityID the connection no longer uses.
      spEntityId: `${ISSUER_URL}/${TENANT}/${METHOD_ID}`,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).not.toBe("success")
  })
})

describe("SAML SP — signature posture", () => {
  const responseOnly: Partial<SamlSpConfig> = {
    requireSignedAssertion: false,
    requireSignedResponse: true,
  }

  test("a Response-signed assertion is REJECTED under the defaults", async () => {
    const primed = await authnRequestXml(config())
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
      signResponseInstead: true,
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).not.toBe("success")
  })

  test("...and ACCEPTED once the connection opts into response-only signing", async () => {
    const primed = await authnRequestXml(config(responseOnly))
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
      signResponseInstead: true,
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("success")
  })

  test("response-only mode still rejects a wrong-key signature", async () => {
    const primed = await authnRequestXml(config(responseOnly))
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
      signResponseInstead: true,
      wrongKey: true,
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).not.toBe("success")
  })

  test("response-only mode still rejects an entirely unsigned message", async () => {
    const primed = await authnRequestXml(config(responseOnly))
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
      unsigned: true,
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).not.toBe("success")
  })
})

describe("SAML SP — AuthnStatement surfacing", () => {
  test("SessionNotOnOrAfter + AuthnContextClassRef reach the host", async () => {
    const primed = await authnRequestXml(config())
    const expiry = Date.now() + 8 * 60 * 60 * 1000
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
      sessionNotOnOrAfter: expiry,
      authnContextClassRef: MFA_CLASS,
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok || res.value.kind !== "success") throw new Error("not success")
    const props = res.value.properties as SamlSpProperties

    // Second-resolution: the fixture serializes to ISO, so compare at
    // that granularity rather than to the raw millisecond input.
    expect(props.sessionNotOnOrAfter).toBe(
      Date.parse(new Date(expiry).toISOString()),
    )
    expect(props.authnContextClassRef).toBe(MFA_CLASS)
  })

  test("both omitted when the assertion carries neither", async () => {
    const primed = await authnRequestXml(config())
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
      authnContextClassRef: "",
    })
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok || res.value.kind !== "success") throw new Error("not success")
    const props = res.value.properties as SamlSpProperties
    expect(props.sessionNotOnOrAfter).toBeUndefined()
    expect(props.authnContextClassRef).toBeUndefined()
  })

  test("authnInstant comes from the assertion, not the clock", async () => {
    const primed = await authnRequestXml(config())
    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice",
    })
    const before = Date.now()
    const res = await postAssertion(primed, saml)
    expect(res.ok).toBe(true)
    if (!res.ok || res.value.kind !== "success") throw new Error("not success")
    const props = res.value.properties as SamlSpProperties
    // The fixture stamps AuthnInstant at build time and truncates to
    // whole seconds; a Date.now() fallback would land at or after
    // `before`, so anything earlier proves it was read from the XML.
    expect(props.authnInstant).toBeLessThanOrEqual(before)
    expect(props.authnInstant).toBeGreaterThan(before - 60_000)
  })
})
