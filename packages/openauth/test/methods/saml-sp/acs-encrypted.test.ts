/**
 * Encrypted-assertion support behind the `allowEncryptedAssertions`
 * flag (conformance 17/18), end-to-end through `dispatchMethod` — same
 * harness as `acs.test.ts`, but the (still-signed) assertion arrives
 * wrapped in `<saml:EncryptedAssertion>`.
 *
 *   - flag **on** + `decryptionKey` → node-saml decrypts, the inner
 *     XML-DSig is still enforced, `success` with mapped properties.
 *   - flag **off** (no `decryptionPvk`) → rejected, with an operator-
 *     legible reason (the connection is not configured for it).
 *
 * Plus the truthful-metadata invariant: a `use="encryption"`
 * KeyDescriptor is advertised iff the connection accepts encrypted
 * assertions.
 */
import { describe, expect, test } from "bun:test"
import { inflateRawSync } from "node:zlib"

import { MemorySessionStore } from "../../../src/adapters/memory"
import { dispatchMethod } from "../../../src/domain/method-dispatch"
import { samlSpFactory } from "../../../src/methods/saml-sp/factory"
import { buildSpMetadataXml } from "../../../src/methods/saml-sp/metadata"
import type {
  SamlSpConfig,
  SamlSpProperties,
} from "../../../src/methods/saml-sp/types"
import type { AnyAuthMethodFactory } from "../../../src/types/method"
import { asTenantId, type TenantContext } from "../../../src/types/tenant"

import { buildTenant } from "../../helpers/tenant"
import { makeFlow } from "../../ports/fixtures"
import {
  buildEncryptedSamlResponse,
  DECRYPTION_CERT,
  DECRYPTION_PRIVATE_KEY,
} from "./fixtures/build-encrypted"
import { IDP_CERT } from "./fixtures/build-response"

const ISSUER_URL = "https://idp.example"
const TENANT = "acme"
const METHOD_ID = "corp-saml"
const IDP_ENTITY = "https://corp-idp.example/saml/metadata"
const STATE_ENVELOPE = "state.envelope.mac"

function config(encrypted: boolean): SamlSpConfig {
  return {
    idp: {
      entityId: IDP_ENTITY,
      ssoUrl: "https://corp-idp.example/sso",
      nameIdFormat: "persistent",
      signingCerts: [{ pem: IDP_CERT }],
    },
    attributeMapping: { subject: { source: "nameId" } },
    ...(encrypted
      ? {
          allowEncryptedAssertions: true,
          decryptionKey: {
            privateKeyPem: DECRYPTION_PRIVATE_KEY,
            certPem: DECRYPTION_CERT,
          },
        }
      : {}),
  }
}

async function buildMethod(encrypted: boolean) {
  const factory: AnyAuthMethodFactory = samlSpFactory
  return factory.build({
    id: METHOD_ID,
    kind: "saml-sp",
    tenantId: asTenantId(TENANT),
    config: config(encrypted),
  })
}

async function tenantCtx(): Promise<TenantContext> {
  return {
    id: asTenantId(TENANT),
    config: await buildTenant({ id: TENANT }),
    request: { raw: new Request(`${ISSUER_URL}/authorize`), custom: {} },
  }
}

async function primeAuthnRequest(
  store: MemorySessionStore,
  method: Awaited<ReturnType<typeof buildMethod>>,
  tenant: TenantContext,
) {
  const flow = makeFlow({
    flowId: "saml-flow-enc",
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
  return dispatchMethod({
    method,
    route: "GET /callback",
    tenant,
    request: new Request(`${ISSUER_URL}/cb/${METHOD_ID}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }),
    subPath: "/callback",
    flow,
    cookies: new Map(),
    sessionStore: store,
    issuerUrl: ISSUER_URL,
    dispatch: null,
  })
}

describe("SAML SP — encrypted assertions", () => {
  test("flag ON + decryptionKey → decrypted, signature still enforced, success", async () => {
    const store = new MemorySessionStore()
    const method = await buildMethod(true)
    const tenant = await tenantCtx()
    const primed = await primeAuthnRequest(store, method, tenant)

    const saml = await buildEncryptedSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "enc-user-001",
    })
    const res = await postAssertion(store, method, tenant, primed.flow, saml)

    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("success")
    if (res.value.kind !== "success") return
    expect(res.value.providerSubject).toBe("enc-user-001")
    const props = res.value.properties as SamlSpProperties
    expect(props.nameId.value).toBe("enc-user-001")
  })

  test("flag OFF → encrypted assertion rejected with an operator-legible reason", async () => {
    const store = new MemorySessionStore()
    const method = await buildMethod(false)
    const tenant = await tenantCtx()
    const primed = await primeAuthnRequest(store, method, tenant)

    const saml = await buildEncryptedSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "enc-user-002",
    })
    const res = await postAssertion(store, method, tenant, primed.flow, saml)

    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind === "success").toBe(false)
    expect(res.value.kind).toBe("denied")
    if (res.value.kind !== "denied") return
    expect(res.value.reason.toLowerCase()).toContain("encrypted assertion")
    expect(res.value.reason).toContain("allowEncryptedAssertions")
  })

  test('metadata advertises a use="encryption" KeyDescriptor iff configured', async () => {
    const withEnc = buildSpMetadataXml({
      spEntityId: "https://idp.example/acme/corp-saml",
      acsUrl: "https://idp.example/cb/corp-saml",
      encryptionCertPem: DECRYPTION_CERT,
    })
    expect(withEnc).toContain('<md:KeyDescriptor use="encryption">')
    expect(withEnc).toContain("<ds:X509Certificate>")
    // No signing key configured here → no signing descriptor.
    expect(withEnc).not.toContain('use="signing"')
    expect(withEnc).toContain('AuthnRequestsSigned="false"')

    const without = buildSpMetadataXml({
      spEntityId: "https://idp.example/acme/corp-saml",
      acsUrl: "https://idp.example/cb/corp-saml",
    })
    expect(without).not.toContain("KeyDescriptor")
  })
})
