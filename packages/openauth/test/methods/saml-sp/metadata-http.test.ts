/**
 * SP metadata through the **real HTTP router** (`idp.handle`).
 *
 * `metadata.test.ts` covers the builder + domain dispatch;
 * `method-route-public.test.ts` covers the domain gate. This file
 * covers the piece neither does: the reordered `makeMethodRouteHandler`
 * fast-path end-to-end — and the security-critical regression that the
 * flow-cookie gate is still fail-closed for every non-public request.
 */
import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../../src/adapters/memory"
import { createIdP } from "../../../src/index"
import { samlSpFactory } from "../../../src/methods/saml-sp/factory"
import type { AuthError } from "../../../src/types/error"
import { asTenantId, type TenantId } from "../../../src/types/tenant"
import { ok, type Result } from "../../../src/types/result"

import { buildStateKeys } from "../../helpers/state-keys"
import { buildTenant } from "../../helpers/tenant"

const ISSUER = "https://idp.example"
const MID = "corp-saml"

async function buildSamlIdp() {
  const tenant = await buildTenant({
    methods: [
      {
        id: MID,
        kind: "saml-sp",
        config: {
          idp: {
            entityId: "https://corp-idp.example/meta",
            ssoUrl: "https://corp-idp.example/sso",
            nameIdFormat: "persistent",
            signingCerts: [{ pem: "x" }],
          },
          attributeMapping: { subject: { source: "nameId" } },
        },
      },
    ],
  })
  const keyStore = new MemoryKeyStore()
  const idp = createIdP({
    resolveTenant: async (
      _req: Request,
    ): Promise<Result<TenantId, AuthError>> => ok(asTenantId(tenant.id)),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore }),
    sessionStore: new MemorySessionStore(),
    keyStore,
    auditLog: new MemoryAuditLog(),
    issuerUrl: ISSUER,
    methods: { "saml-sp": samlSpFactory as never },
    subjects: {} as never,
    success: async ({ providerSubject }) =>
      ({ type: "user", properties: { userId: providerSubject } }) as never,
  })
  return idp
}

describe("SAML SP metadata over HTTP (idp.handle)", () => {
  test("GET /m/<id>/metadata with NO cookie → 200 samlmetadata+xml, cached", async () => {
    const idp = await buildSamlIdp()
    const res = await idp.handle(
      new Request(`${ISSUER}/m/${MID}/metadata`),
    )
    expect(res.status).toBe(200)
    expect(res.headers.get("content-type")).toBe(
      "application/samlmetadata+xml",
    )
    // The framework owns Cache-Control; the public path must serialize
    // the method's CachePolicy (the old /m/* challenge path did not).
    expect(res.headers.get("cache-control")).toContain("s-maxage=300")
    const body = await res.text()
    expect(body).toContain("<md:EntityDescriptor")
    expect(body).toContain('entityID="https://idp.example/acme/corp-saml"')
    expect(body).toContain(
      'Location="https://idp.example/cb/corp-saml"',
    )
  })

  test("FAIL-CLOSED: non-public /m route with no cookie → original 400", async () => {
    const idp = await buildSamlIdp()
    // "GET /authorize" is a real SAML route but NOT in publicRoutes —
    // it must still hit the unchanged flow-cookie gate.
    const r1 = await idp.handle(
      new Request(`${ISSUER}/m/${MID}/authorize`),
    )
    expect(r1.status).toBe(400)
    const b1 = await r1.text()
    expect(b1).toContain("invalid_request")
    expect(b1.toLowerCase()).toContain("flow")
    expect(b1).not.toContain("EntityDescriptor")

    // Verb sensitivity: "POST /metadata" is a different route key,
    // NOT public — must also fail closed without a cookie.
    const r2 = await idp.handle(
      new Request(`${ISSUER}/m/${MID}/metadata`, { method: "POST" }),
    )
    expect(r2.status).toBe(400)
    expect((await r2.text()).toLowerCase()).toContain("flow")
  })

  test("public route is served even when a (junk) flow cookie is present", async () => {
    const idp = await buildSamlIdp()
    const res = await idp.handle(
      new Request(`${ISSUER}/m/${MID}/metadata`, {
        headers: { cookie: "idp.flow=not-a-real-flow-id" },
      }),
    )
    // Public path ignores the cookie entirely — it must not try to
    // read/consume the (bogus) flow and 4xx.
    expect(res.status).toBe(200)
    expect(res.headers.get("content-type")).toBe(
      "application/samlmetadata+xml",
    )
  })

  test("unknown methodId on the public path does not 200", async () => {
    const idp = await buildSamlIdp()
    const res = await idp.handle(
      new Request(`${ISSUER}/m/no-such-method/metadata`),
    )
    // Not public (method doesn't resolve) → falls through to the
    // cookie-gated path → 400, never a metadata 200.
    expect(res.status).not.toBe(200)
  })
})
