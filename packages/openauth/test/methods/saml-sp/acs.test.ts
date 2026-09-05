/**
 * ACS verification gauntlet, end-to-end through `dispatchMethod`.
 *
 * Each test primes a real AuthnRequest first (so node-saml's
 * `InResponseTo` cache — methodScratch-backed — has the outstanding
 * request id and the SP entityID / ACS URL are committed to
 * `methodState`), then POSTs a fixture Response to the
 * `"GET /callback"` route. The valid fixture must `success` with
 * correctly mapped properties; every attack fixture must NOT reach
 * `success`.
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

function config(): SamlSpConfig {
  return {
    idp: {
      entityId: IDP_ENTITY,
      ssoUrl: "https://corp-idp.example/sso",
      nameIdFormat: "persistent",
      signingCerts: [{ pem: IDP_CERT }],
    },
    attributeMapping: {
      subject: { source: "nameId" },
      email: { source: "attribute", name: "email" },
      groups: { source: "attribute", name: "groups" },
      emailVerified: { source: "literal", value: true },
    },
  }
}

async function buildMethod() {
  const factory: AnyAuthMethodFactory = samlSpFactory
  return factory.build({
    id: METHOD_ID,
    kind: "saml-sp",
    tenantId: asTenantId(TENANT),
    config: config(),
  })
}

async function tenantCtx(): Promise<TenantContext> {
  return {
    id: asTenantId(TENANT),
    config: await buildTenant({ id: TENANT }),
    request: { raw: new Request(`${ISSUER_URL}/authorize`), custom: {} },
  }
}

/**
 * Run GET /authorize, returning the decoded AuthnRequest id and the
 * SP binding the handler committed to `methodState`.
 */
async function primeAuthnRequest(
  store: MemorySessionStore,
  method: Awaited<ReturnType<typeof buildMethod>>,
  tenant: TenantContext,
) {
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
    dispatch: {
      state: STATE_ENVELOPE,
      callbackUrl: `${ISSUER_URL}/cb/${METHOD_ID}`,
      issuerUrl: ISSUER_URL,
    },
  })
  if (!res.ok || res.value.kind !== "challenge") {
    throw new Error("priming AuthnRequest failed")
  }
  const loc = res.value.response.headers.get("location") as string
  const samlRequest = new URL(loc).searchParams.get("SAMLRequest") as string
  const xml = inflateRawSync(Buffer.from(samlRequest, "base64")).toString(
    "utf8",
  )
  const requestId = /\sID="([^"]+)"/.exec(xml)?.[1] as string

  const updated = await store.readFlow(flow.flowId)
  if (!updated.ok) throw new Error("flow vanished")
  const st = updated.value.methodState as {
    spEntityId: string
    acsUrl: string
  }
  return { requestId, flow: updated.value, ...st }
}

async function postAssertion(
  store: MemorySessionStore,
  method: Awaited<ReturnType<typeof buildMethod>>,
  tenant: TenantContext,
  flow: Awaited<ReturnType<typeof primeAuthnRequest>>["flow"],
  samlResponseB64: string,
) {
  const body = new URLSearchParams({
    SAMLResponse: samlResponseB64,
    RelayState: STATE_ENVELOPE,
  }).toString()
  const req = new Request(`${ISSUER_URL}/cb/${METHOD_ID}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  })
  return dispatchMethod({
    method,
    route: "GET /callback",
    tenant,
    request: req,
    subPath: "/callback",
    flow,
    cookies: new Map(),
    sessionStore: store,
    dispatch: null,
  })
}

describe("SAML SP — ACS gauntlet", () => {
  test("valid signed assertion → success with mapped properties", async () => {
    const store = new MemorySessionStore()
    const method = await buildMethod()
    const tenant = await tenantCtx()
    const primed = await primeAuthnRequest(store, method, tenant)

    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice-persistent-001",
      attributes: { email: "alice@corp.example", groups: ["eng", "admins"] },
    })
    const res = await postAssertion(store, method, tenant, primed.flow, saml)

    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("success")
    if (res.value.kind !== "success") return
    const props = res.value.properties as SamlSpProperties
    expect(res.value.providerSubject).toBe("alice-persistent-001")
    expect(props.nameId.value).toBe("alice-persistent-001")
    expect(props.nameId.format).toBe("persistent")
    expect(props.attributes.email).toBe("alice@corp.example")
    expect(props.attributes.groups).toEqual(["eng", "admins"])
    expect(props.attributes.emailVerified).toBe("true")
    expect(props.sessionIndex).toBe("sess-1")
    expect(props.raw.responseXml.length).toBeGreaterThan(0)
  })

  // node-saml enforces: signature over signed references only (1-3,10,11),
  // Issuer (4), AudienceRestriction (5), Conditions/SubjectConfirmation
  // timestamps (8), InResponseTo single-use (7,9). It does NOT enforce
  // SubjectConfirmationData/@Recipient (6) — that explicit check now
  // lives in `checkRecipient` (acs.ts), reading the *signed* assertion.
  // The `badRecipient` / `noRecipient` cases below exercise it.
  const attacks: Array<{ name: string; opts: Record<string, boolean> }> = [
    { name: "unsigned assertion", opts: { unsigned: true } },
    { name: "signed with wrong key", opts: { wrongKey: true } },
    { name: "audience mismatch", opts: { badAudience: true } },
    { name: "expired conditions", opts: { expired: true } },
    { name: "signature-wrapping (XSW)", opts: { xsw: true } },
    // Gauntlet item 6 — Recipient bound to a different ACS.
    { name: "recipient mismatch", opts: { badRecipient: true } },
    // Item 6 — assertion carries no Recipient to bind it at all.
    { name: "recipient absent", opts: { noRecipient: true } },
  ]

  for (const { name, opts } of attacks) {
    test(`attack rejected: ${name}`, async () => {
      const store = new MemorySessionStore()
      const method = await buildMethod()
      const tenant = await tenantCtx()
      const primed = await primeAuthnRequest(store, method, tenant)

      const saml = buildSamlResponse({
        requestId: primed.requestId,
        spEntityId: primed.spEntityId,
        acsUrl: primed.acsUrl,
        idpEntityId: IDP_ENTITY,
        ...opts,
      })
      const res = await postAssertion(store, method, tenant, primed.flow, saml)

      expect(res.ok).toBe(true)
      if (!res.ok) return
      // Must NOT authenticate. denied (controlled) or error (infra),
      // never success.
      expect(res.value.kind === "success").toBe(false)
      expect(["denied", "error"]).toContain(res.value.kind)
    })
  }

  test("XXE: external entity is never expanded into the subject", async () => {
    const store = new MemorySessionStore()
    const method = await buildMethod()
    const tenant = await tenantCtx()
    const primed = await primeAuthnRequest(store, method, tenant)

    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      xxe: true,
    })
    const res = await postAssertion(store, method, tenant, primed.flow, saml)

    // The security property is "no entity expansion / no file
    // disclosure" — NOT necessarily rejection. Whether node-saml
    // denies (DTD refused / digest mismatch) or succeeds with the
    // literal unexpanded `&xxe;`, the one thing that must never happen
    // is /etc/passwd content surfacing in the subject.
    expect(res.ok).toBe(true)
    if (!res.ok) return
    const blob = JSON.stringify(res.value)
    expect(blob.includes("root:")).toBe(false)
    expect(blob.includes("/bin/")).toBe(false)
    if (res.value.kind === "success") {
      expect(res.value.providerSubject).not.toContain("root:")
    }
  })

  test("replay rejected: same Response twice (InResponseTo single-use)", async () => {
    const store = new MemorySessionStore()
    const method = await buildMethod()
    const tenant = await tenantCtx()
    const primed = await primeAuthnRequest(store, method, tenant)

    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "bob-001",
    })
    const first = await postAssertion(store, method, tenant, primed.flow, saml)
    expect(first.ok && first.value.kind).toBe("success")

    const second = await postAssertion(store, method, tenant, primed.flow, saml)
    expect(second.ok).toBe(true)
    if (!second.ok) return
    expect(second.value.kind === "success").toBe(false)
  })
})
