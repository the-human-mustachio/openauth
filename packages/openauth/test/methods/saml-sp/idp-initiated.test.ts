/**
 * IdP-initiated SSO (SAML-AD7) through the **real router**
 * (`idp.handle`). An unsolicited signed Response — no AuthnRequest, no
 * state envelope, no flow — POSTed to the SP's single ACS
 * (`/cb/<methodId>`, exactly what the metadata advertises) must:
 *
 *   - mint a code and 302 to the operator-configured defaultRedirectUri;
 *   - reject a replay (assertion-ID dedup, since there is no
 *     InResponseTo single-use to lean on);
 *   - stay `invalid_request` when the instance did NOT opt in
 *     (conservative default unchanged);
 *   - never treat `RelayState` as a redirect target (open-redirect).
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
import { buildSamlResponse, IDP_CERT } from "./fixtures/build-response"

const ISSUER = "https://idp.example"
const TENANT = "acme"
const MID = "corp-saml"
const IDP_ENTITY = "https://corp-idp.example/saml/metadata"
const RP_REDIRECT = "https://app.example/callback" // buildTenant default

async function buildSamlIdp(withIdpInitiated: boolean) {
  const tenant = await buildTenant({
    methods: [
      {
        id: MID,
        kind: "saml-sp",
        config: {
          idp: {
            entityId: IDP_ENTITY,
            ssoUrl: "https://corp-idp.example/sso",
            signingCerts: [{ pem: IDP_CERT }],
          },
          attributeMapping: { subject: { source: "nameId" } },
          ...(withIdpInitiated
            ? {
                idpInitiated: {
                  defaultClientId: "rp-1",
                  defaultRedirectUri: RP_REDIRECT,
                  defaultScopes: ["openid"],
                },
              }
            : {}),
        },
      },
    ],
  })
  const keyStore = new MemoryKeyStore()
  return createIdP({
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
}

function unsolicitedAssertion(extra: { nameId?: string } = {}) {
  return buildSamlResponse({
    requestId: "unused-for-unsolicited",
    spEntityId: `${ISSUER}/${TENANT}/${MID}`,
    acsUrl: `${ISSUER}/cb/${MID}`,
    idpEntityId: IDP_ENTITY,
    unsolicited: true,
    nameId: extra.nameId ?? "idp-init-user-001",
  })
}

function acsPost(body: Record<string, string>): Request {
  return new Request(`${ISSUER}/cb/${MID}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  })
}

describe("SAML SP — IdP-initiated SSO (idp.handle)", () => {
  test("unsolicited signed Response → 302 to defaultRedirectUri with ?code=", async () => {
    const idp = await buildSamlIdp(true)
    const res = await idp.handle(
      acsPost({ SAMLResponse: unsolicitedAssertion() }),
    )
    expect(res.status).toBe(302)
    const loc = res.headers.get("location") as string
    expect(loc.startsWith(`${RP_REDIRECT}?`)).toBe(true)
    const u = new URL(loc)
    expect(u.searchParams.get("code")).toBeTruthy()
    // No RP-supplied OAuth state in an unsolicited flow.
    expect(u.searchParams.get("state")).toBeNull()
  })

  test("replay of the same unsolicited assertion is rejected", async () => {
    const idp = await buildSamlIdp(true)
    const saml = unsolicitedAssertion({ nameId: "replay-victim" })
    const first = await idp.handle(acsPost({ SAMLResponse: saml }))
    expect(first.status).toBe(302)
    const second = await idp.handle(acsPost({ SAMLResponse: saml }))
    // Assertion-ID dedup → denied → 403, never another code.
    expect(second.status).not.toBe(302)
    expect(await second.text()).toContain("access_denied")
  })

  test("not opted in (no idpInitiated) → unchanged invalid_request", async () => {
    const idp = await buildSamlIdp(false)
    const res = await idp.handle(
      acsPost({ SAMLResponse: unsolicitedAssertion() }),
    )
    expect(res.status).toBe(400)
    expect((await res.text()).toLowerCase()).toContain("state")
  })

  test("hostile RelayState is never used as the redirect target", async () => {
    const idp = await buildSamlIdp(true)
    const res = await idp.handle(
      acsPost({
        SAMLResponse: unsolicitedAssertion(),
        RelayState: "https://evil.example/steal",
      }),
    )
    expect(res.status).toBe(302)
    const loc = res.headers.get("location") as string
    expect(loc.startsWith(RP_REDIRECT)).toBe(true)
    expect(loc).not.toContain("evil.example")
  })
})
