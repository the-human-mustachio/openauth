/**
 * SAML SP-initiated SSO, end-to-end against a **production** SessionStore.
 *
 * The memory-backed gauntlet (`acs.test.ts`) proves correctness on a
 * single-process store. This file proves the Phase 1.5 blocker is gone:
 * the same SP-initiated flow — including InResponseTo single-use replay
 * protection, which rides `methodScratch` — works when `methodScratch`
 * is backed by `PostgresSessionStore` rather than memory.
 *
 * `dispatchMethod` builds `MethodContext.methodScratch` from the injected
 * `SessionStore`'s `saveScratch` / `readScratch` / `deleteScratch`, so
 * swapping the store here exercises the real Postgres scratch path:
 * node-saml writes the outstanding request id at AuthnRequest time and
 * reads it back at the ACS. Backed by PGlite (in-process WASM Postgres);
 * no external services.
 */
import { PGlite } from "@electric-sql/pglite"
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test"
import { inflateRawSync } from "node:zlib"

import {
  fromPGlite,
  migrate,
  PostgresSessionStore,
  type PostgresExecutor,
} from "../../../src/adapters/postgres"
import { dispatchMethod } from "../../../src/domain/method-dispatch"
import { samlSpFactory } from "../../../src/methods/saml-sp/factory"
import type {
  SamlSpConfig,
  SamlSpProperties,
} from "../../../src/methods/saml-sp/types"
import type { SessionStore } from "../../../src/ports/session-store"
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

let pglite: PGlite
let exec: PostgresExecutor

beforeAll(async () => {
  pglite = new PGlite()
  exec = fromPGlite(pglite)
  await migrate(exec)
})

afterAll(async () => {
  await pglite.close()
})

beforeEach(async () => {
  await exec.query(`TRUNCATE TABLE openauth_flows CASCADE`)
  await exec.query(`TRUNCATE TABLE openauth_scratch CASCADE`)
})

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

async function primeAuthnRequest(
  store: SessionStore,
  method: Awaited<ReturnType<typeof buildMethod>>,
  tenant: TenantContext,
) {
  const flow = makeFlow({
    flowId: "saml-flow-pg-1",
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
  store: SessionStore,
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
    issuerUrl: ISSUER_URL,
    dispatch: null,
  })
}

describe("SAML SP — SP-initiated SSO on Postgres SessionStore", () => {
  test("valid signed assertion → success (scratch round-trips through Postgres)", async () => {
    const store = new PostgresSessionStore({ exec })
    const method = await buildMethod()
    const tenant = await tenantCtx()
    const primed = await primeAuthnRequest(store, method, tenant)

    const saml = buildSamlResponse({
      requestId: primed.requestId,
      spEntityId: primed.spEntityId,
      acsUrl: primed.acsUrl,
      idpEntityId: IDP_ENTITY,
      nameId: "alice-persistent-001",
      attributes: { email: "alice@corp.example" },
    })
    const res = await postAssertion(store, method, tenant, primed.flow, saml)

    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.kind).toBe("success")
    if (res.value.kind !== "success") return
    const props = res.value.properties as SamlSpProperties
    expect(res.value.providerSubject).toBe("alice-persistent-001")
    expect(props.nameId.value).toBe("alice-persistent-001")
    expect(props.attributes.email).toBe("alice@corp.example")
  })

  test("replay rejected: same Response twice (InResponseTo single-use via Postgres scratch)", async () => {
    const store = new PostgresSessionStore({ exec })
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
    // The InResponseTo entry was consumed from Postgres scratch on the
    // first ACS; the replay must not re-authenticate.
    expect(second.value.kind === "success").toBe(false)
  })
})
