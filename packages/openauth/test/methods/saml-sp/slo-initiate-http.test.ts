/**
 * SP-initiated front-channel Single Logout through the **real HTTP
 * router** (`idp.handle`) — the send half + the IdP `LogoutResponse`
 * return leg, completing the conformance-16 round-trip.
 *
 * Boundary checks that matter here:
 *   - SP-initiated send is **pure protocol propagation** — it must NOT
 *     fire `onLogout` / revoke library tokens (that is `/end_session`'s
 *     job, deliberately not auto-bridged).
 *   - The host must name the subject (the library never persisted the
 *     NameID↔subject map); missing `nameId` is refused.
 *   - The `/logout` route is gated public exactly like `/sls`.
 *   - The IdP's `LogoutResponse` is signature-verified on the return
 *     leg; a forged one is denied.
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
import type { LogoutEventInput } from "../../../src/types/idp"
import type { AuthError } from "../../../src/types/error"
import { asTenantId, type TenantId } from "../../../src/types/tenant"
import { ok, type Result } from "../../../src/types/result"

import { buildStateKeys } from "../../helpers/state-keys"
import { buildTenant } from "../../helpers/tenant"
import { IDP_CERT, postLogoutResponse } from "./fixtures/build-logout"

const ISSUER = "https://idp.example"
const MID = "corp-saml"
const IDP_ENTITY = "https://corp-idp.example/meta"
const SLO_URL = "https://corp-idp.example/slo"
const SLS_URL = `${ISSUER}/m/${MID}/sls`
const LOGOUT_URL = `${ISSUER}/m/${MID}/logout`

async function buildSamlIdp(opts?: { withSlo?: boolean }) {
  const withSlo = opts?.withSlo ?? true
  const tenant = await buildTenant({
    methods: [
      {
        id: MID,
        kind: "saml-sp",
        config: {
          idp: {
            entityId: IDP_ENTITY,
            ssoUrl: "https://corp-idp.example/sso",
            ...(withSlo ? { sloUrl: SLO_URL } : {}),
            nameIdFormat: "persistent",
            signingCerts: [{ pem: IDP_CERT }],
          },
          attributeMapping: { subject: { source: "nameId" } },
        },
      },
    ],
  })
  const keyStore = new MemoryKeyStore()
  const audit = new MemoryAuditLog()
  const onLogoutCalls: LogoutEventInput[] = []
  const idp = createIdP({
    resolveTenant: async (
      _req: Request,
    ): Promise<Result<TenantId, AuthError>> => ok(asTenantId(tenant.id)),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore }),
    sessionStore: new MemorySessionStore(),
    keyStore,
    auditLog: audit,
    issuerUrl: ISSUER,
    methods: { "saml-sp": samlSpFactory as never },
    subjects: {} as never,
    success: async ({ providerSubject }) =>
      ({ type: "user", properties: { userId: providerSubject } }) as never,
    onLogout: async (input) => {
      onLogoutCalls.push(input)
      return { revokeSubject: "subj-1" }
    },
  })
  return { idp, audit, onLogoutCalls }
}

const form = (o: Record<string, string>) =>
  new URLSearchParams(o).toString()

describe("SAML SP-initiated SLO over HTTP (idp.handle)", () => {
  test("POST /logout → 302 signed-less LogoutRequest to IdP SLO; NO token side effect", async () => {
    const { idp, audit, onLogoutCalls } = await buildSamlIdp()
    const res = await idp.handle(
      new Request(LOGOUT_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({
          nameId: "alice@corp.example",
          sessionIndex: "sess-99",
          relayState: "back-to-app",
        }),
      }),
    )
    expect(res.status).toBe(302)
    const loc = res.headers.get("location") ?? ""
    expect(loc.startsWith(SLO_URL)).toBe(true)
    expect(loc).toContain("SAMLRequest=")

    // Propagation only — the framework logout side effect must NOT run.
    expect(onLogoutCalls).toHaveLength(0)
    expect(audit.byKind("token_revoked")).toHaveLength(0)
    expect(audit.byKind("session_logout")).toHaveLength(0)
  })

  test("POST /logout with no nameId → denied (the host must name the subject)", async () => {
    const { idp } = await buildSamlIdp()
    const res = await idp.handle(
      new Request(LOGOUT_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ sessionIndex: "sess-99" }),
      }),
    )
    expect(res.status).toBe(403)
    expect((await res.text()).toLowerCase()).toContain("nameid")
  })

  test("return leg: signed IdP LogoutResponse → /sls → 200, no side effect", async () => {
    const { idp, onLogoutCalls, audit } = await buildSamlIdp()
    const samlResponse = postLogoutResponse({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      inResponseTo: "_sp_req_1",
    })
    const res = await idp.handle(
      new Request(SLS_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ SAMLResponse: samlResponse }),
      }),
    )
    expect(res.status).toBe(200)
    expect((await res.text()).toLowerCase()).toContain("logged out")
    // The response leg confirms; it does not itself revoke.
    expect(onLogoutCalls).toHaveLength(0)
    expect(audit.byKind("session_logout")).toHaveLength(0)
  })

  test("FAIL-CLOSED: forged (wrong-key) LogoutResponse → denied", async () => {
    const { idp } = await buildSamlIdp()
    const samlResponse = postLogoutResponse({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      wrongKey: true,
    })
    const res = await idp.handle(
      new Request(SLS_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ SAMLResponse: samlResponse }),
      }),
    )
    expect(res.status).toBe(403)
  })

  test("GATING: no idp.sloUrl → POST /logout is not public → cookie-gated 400", async () => {
    const { idp } = await buildSamlIdp({ withSlo: false })
    const res = await idp.handle(
      new Request(LOGOUT_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ nameId: "alice@corp.example" }),
      }),
    )
    expect(res.status).toBe(400)
    expect(res.status).not.toBe(302)
  })
})
