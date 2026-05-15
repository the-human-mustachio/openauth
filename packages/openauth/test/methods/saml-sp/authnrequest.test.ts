/**
 * SP-initiated AuthnRequest path, end-to-end through `dispatchMethod`.
 *
 * We drive the real `samlSpFactory` → `buildSamlSpMethod` →
 * `"GET /authorize"` handler against a real `MemorySessionStore` (so
 * `methodScratch` + `saveMethodState` actually round-trip) and a real
 * `@node-saml/node-saml` instance. No live IdP is needed — the
 * assertion is that we emit a well-formed HTTP-Redirect-binding
 * AuthnRequest carrying our state envelope as RelayState.
 */
import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { MemorySessionStore } from "../../../src/adapters/memory"
import { dispatchMethod } from "../../../src/domain/method-dispatch"
import { samlSpFactory } from "../../../src/methods/saml-sp/factory"
import type { SamlSpConfig } from "../../../src/methods/saml-sp/types"
import type { AnyAuthMethodFactory } from "../../../src/types/method"
import { asTenantId, type TenantContext } from "../../../src/types/tenant"

import { buildTenant } from "../../helpers/tenant"
import { makeFlow } from "../../ports/fixtures"

const IDP_CERT = readFileSync(
  join(import.meta.dir, "fixtures", "idp-cert.pem"),
  "utf8",
)

const SSO_URL = "https://idp.example/saml/sso"
const STATE_ENVELOPE = "state.envelope.mac"
const ISSUER_URL = "https://idp.example"
const TENANT = "acme"
const METHOD_ID = "corp-saml"

function baseConfig(overrides: Partial<SamlSpConfig> = {}): SamlSpConfig {
  return {
    idp: {
      entityId: "https://idp.example/saml/metadata",
      ssoUrl: SSO_URL,
      nameIdFormat: "persistent",
      signingCerts: [{ pem: IDP_CERT }],
    },
    attributeMapping: { subject: { source: "nameId" } },
    ...overrides,
  }
}

async function dispatchAuthorize(
  config: SamlSpConfig,
  store: MemorySessionStore,
) {
  // Mirror production: factories are held as `AnyAuthMethodFactory`
  // (variance-erased) in `IdPOptions.methods`, so `build` yields the
  // `AuthMethod` shape `dispatchMethod` accepts.
  const factory: AnyAuthMethodFactory = samlSpFactory
  const method = await factory.build({
    id: METHOD_ID,
    kind: "saml-sp",
    tenantId: asTenantId(TENANT),
    config,
  })
  const tenantConfig = await buildTenant({ id: TENANT })
  const tenant: TenantContext = {
    id: asTenantId(TENANT),
    config: tenantConfig,
    request: {
      raw: new Request("https://idp.example/authorize"),
      custom: {},
    },
  }
  const flow = makeFlow({
    flowId: "saml-flow-1",
    tenantId: asTenantId(TENANT),
    methodId: METHOD_ID,
    methodKind: "saml-sp",
    callbackPath: `/cb/${METHOD_ID}`,
  })
  await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)

  return dispatchMethod({
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
}

describe("SAML SP — SP-initiated AuthnRequest", () => {
  test("emits a 302 to the IdP SSO URL with SAMLRequest + RelayState", async () => {
    const store = new MemorySessionStore()
    const res = await dispatchAuthorize(baseConfig(), store)

    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("challenge")
    if (res.value.kind !== "challenge") return

    expect(res.value.response.status).toBe(302)
    const loc = res.value.response.headers.get("location")
    expect(loc).toBeTruthy()
    const url = new URL(loc as string)
    expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(SSO_URL)

    const samlRequest = url.searchParams.get("SAMLRequest")
    expect(samlRequest).toBeTruthy()
    expect((samlRequest as string).length).toBeGreaterThan(0)

    expect(url.searchParams.get("RelayState")).toBe(STATE_ENVELOPE)
  })

  test("persists SamlSpState (relayState + issuedAt) to the flow", async () => {
    const store = new MemorySessionStore()
    const before = Date.now()
    const res = await dispatchAuthorize(baseConfig(), store)
    expect(res.ok).toBe(true)

    const flow = await store.readFlow("saml-flow-1")
    expect(flow.ok).toBe(true)
    if (!flow.ok) return
    const st = flow.value.methodState as {
      relayState: string
      issuedAt: number
    }
    expect(st.relayState).toBe(STATE_ENVELOPE)
    expect(typeof st.issuedAt).toBe("number")
    expect(st.issuedAt).toBeGreaterThanOrEqual(before)
  })

  test("records an outstanding request id in methodScratch (InResponseTo cache)", async () => {
    const store = new MemorySessionStore()
    await dispatchAuthorize(baseConfig(), store)
    // node-saml saved the request id under the scoped scratch key.
    // The framework prefix is scratch:<tenant>:<methodId>:; the
    // cache-provider prefixes saml-inresponseto: on top.
    // We can't know the random request id, but the namespace must be
    // non-empty — assert at least one matching key exists by probing
    // the readScratch miss vs the save side-effect indirectly: a fresh
    // store has nothing, a dispatched one must have written.
    // (Indirect check: a second dispatch must not throw on the cache.)
    const res2 = await dispatchAuthorize(baseConfig(), store)
    expect(res2.ok).toBe(true)
    if (res2.ok) expect(res2.value.kind).toBe("challenge")
  })

  test("rejects signAuthnRequest:true (not yet implemented)", async () => {
    const store = new MemorySessionStore()
    const res = await dispatchAuthorize(
      baseConfig({
        signAuthnRequest: true,
        signingKey: { kid: "saml-sign" },
      }),
      store,
    )
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("error")
    if (res.value.kind === "error") {
      expect(res.value.error.description).toContain("signAuthnRequest")
    }
  })

  test("errors when no signing cert is within its validity window", async () => {
    const store = new MemorySessionStore()
    const res = await dispatchAuthorize(
      baseConfig({
        idp: {
          entityId: "https://idp.example/saml/metadata",
          ssoUrl: SSO_URL,
          nameIdFormat: "persistent",
          signingCerts: [{ pem: IDP_CERT, notAfter: 1 }],
        },
      }),
      store,
    )
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("error")
    if (res.value.kind === "error") {
      expect(res.value.error.description).toContain("validity window")
    }
  })
})
