/**
 * `handlePublicMethodRoute` — the anonymous (flowless) pipeline and,
 * critically, its **fail-closed gate**.
 *
 * The HTTP layer checks `publicRoutes` before routing here, but a
 * no-auth domain entry point must not trust its caller: the gate is
 * re-enforced in the domain function. These tests assert that a route
 * NOT in the method's `publicRoutes` is refused even when the function
 * is called directly with it (i.e. simulating an HTTP-layer mistake),
 * and that a flowless route returning `success` fails loudly rather
 * than authenticating with no flow to consume.
 */
import { describe, expect, test } from "bun:test"

import { MemorySessionStore } from "../../src/adapters/memory"
import { handlePublicMethodRoute } from "../../src/domain/method-route"
import { samlSpFactory } from "../../src/methods/saml-sp/factory"
import type { SamlSpConfig } from "../../src/methods/saml-sp/types"
import type { AnyAuthMethodFactory, AuthMethod } from "../../src/types/method"
import { asTenantId, type TenantContext } from "../../src/types/tenant"

import { buildTenant } from "../helpers/tenant"

const ISSUER = "https://idp.example"
const TENANT = "acme"
const MID = "corp-saml"

const DISPATCH = {
  state: "",
  callbackUrl: `${ISSUER}/cb/${MID}`,
  issuerUrl: ISSUER,
}

const samlConfig: SamlSpConfig = {
  idp: {
    entityId: "https://corp-idp.example/meta",
    ssoUrl: "https://corp-idp.example/sso",
    signingCerts: [{ pem: "x" }],
  },
  attributeMapping: { subject: { source: "nameId" } },
}

async function tenantCtx(): Promise<TenantContext> {
  return {
    id: asTenantId(TENANT),
    config: await buildTenant({ id: TENANT }),
    request: { raw: new Request(`${ISSUER}/m/${MID}/metadata`), custom: {} },
  }
}

async function samlMethod(): Promise<AuthMethod> {
  const f: AnyAuthMethodFactory = samlSpFactory
  return f.build({
    id: MID,
    kind: "saml-sp",
    tenantId: asTenantId(TENANT),
    config: samlConfig,
  })
}

describe("handlePublicMethodRoute", () => {
  test("serves a declared public route (SAML GET /metadata)", async () => {
    const r = await handlePublicMethodRoute(
      {
        rawRequest: new Request(`${ISSUER}/m/${MID}/metadata`),
        tenant: await tenantCtx(),
        method: await samlMethod(),
        route: "GET /metadata",
        subPath: "/metadata",
        dispatch: DISPATCH,
      },
      { sessionStore: new MemorySessionStore() },
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.kind).toBe("challenge")
    if (r.value.kind !== "challenge") return
    expect(r.value.cache).toEqual({ sMaxAge: 300 })
    expect(await r.value.response.text()).toContain("<md:EntityDescriptor")
  })

  test("FAIL-CLOSED: refuses a route not in publicRoutes even if invoked directly", async () => {
    // "GET /authorize" is a real SAML route but is NOT public. The
    // domain gate must reject it regardless of how it was reached.
    const r = await handlePublicMethodRoute(
      {
        rawRequest: new Request(`${ISSUER}/m/${MID}/authorize`),
        tenant: await tenantCtx(),
        method: await samlMethod(),
        route: "GET /authorize",
        subPath: "/authorize",
        dispatch: DISPATCH,
      },
      { sessionStore: new MemorySessionStore() },
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.code).toBe("invalid_request")
    expect(r.error.description).toContain("not public")
  })

  test("a flowless public route returning success fails loudly", async () => {
    const rogue: AuthMethod = {
      id: MID,
      kind: "rogue",
      type: "custom",
      publicRoutes: ["GET /metadata"],
      routes: {
        "GET /metadata": async () => ({
          kind: "success",
          providerSubject: "nobody",
          properties: {},
        }),
      },
    }
    const r = await handlePublicMethodRoute(
      {
        rawRequest: new Request(`${ISSUER}/m/${MID}/metadata`),
        tenant: await tenantCtx(),
        method: rogue,
        route: "GET /metadata",
        subPath: "/metadata",
        dispatch: DISPATCH,
      },
      { sessionStore: new MemorySessionStore() },
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.code).toBe("internal_error")
  })
})
