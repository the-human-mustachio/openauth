/**
 * Front-channel Single Logout through the **real HTTP router**
 * (`idp.handle`) — the full 3b + 3c integration.
 *
 * A cryptographically-signed IdP `LogoutRequest` hits the anonymous
 * `/m/<id>/sls` public route; the SP must verify the XML-DSig, fire
 * the framework's `onLogout` host hook, run `revokeAllForSubject` for
 * the host-named subject, and redirect a signed `LogoutResponse` back
 * to the IdP's SLO endpoint. A forged (wrong-key) request must be
 * denied with no side effect, and a replayed request must be rejected.
 *
 * This is the riskiest layer for Phase 3 — a privileged
 * (token-revoking) action behind an *anonymous* endpoint whose only
 * gate is signature verification — so it is exercised end-to-end, not
 * just at the unit level.
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
import {
  IDP_CERT,
  postLogoutRequest,
  redirectLogoutRequest,
} from "./fixtures/build-logout"

const ISSUER = "https://idp.example"
const MID = "corp-saml"
const IDP_ENTITY = "https://corp-idp.example/meta"
const SLO_URL = "https://corp-idp.example/slo"
const SLS_URL = `${ISSUER}/m/${MID}/sls`

type Harness = {
  idp: ReturnType<typeof createIdP>
  audit: MemoryAuditLog
  onLogoutCalls: LogoutEventInput[]
}

async function buildSamlIdp(opts?: {
  withSlo?: boolean
  /** What onLogout returns. Default: revoke "subj-1". */
  revokeSubject?: string | null
}): Promise<Harness> {
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
  const revoke =
    opts?.revokeSubject === undefined ? "subj-1" : opts.revokeSubject
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
      return revoke ? { revokeSubject: revoke } : undefined
    },
  })
  return { idp, audit, onLogoutCalls }
}

describe("SAML front-channel SLO over HTTP (idp.handle)", () => {
  test("redirect-binding signed LogoutRequest → 302 LogoutResponse + onLogout + revoke + audit", async () => {
    const { idp, audit, onLogoutCalls } = await buildSamlIdp()
    const q = await redirectLogoutRequest({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      nameId: "alice@corp.example",
      sessionIndex: "sess-99",
      relayState: "rs-1",
    })
    const res = await idp.handle(new Request(`${SLS_URL}?${q}`))

    expect(res.status).toBe(302)
    const loc = res.headers.get("location") ?? ""
    expect(loc.startsWith(SLO_URL)).toBe(true)
    expect(loc).toContain("SAMLResponse=")

    // The verified logout reached the host hook intact.
    expect(onLogoutCalls).toHaveLength(1)
    expect(onLogoutCalls[0]?.reason).toBe("upstream_slo")
    expect(onLogoutCalls[0]?.methodId).toBe(MID)
    expect(onLogoutCalls[0]?.methodKind).toBe("saml-sp")
    expect(onLogoutCalls[0]?.nameId).toBe("alice@corp.example")

    // The host-named subject's tokens were revoked, and the logout
    // was audited as an upstream SLO completion.
    const revoked = audit.byKind("token_revoked")
    expect(revoked.some((e) => e.subjectId === "subj-1")).toBe(true)
    const sl = audit.byKind("session_logout")
    expect(sl).toHaveLength(1)
    expect(sl[0]?.via).toBe("upstream_slo")
    expect(sl[0]?.subjectId).toBe("subj-1")
  })

  test("POST-binding signed LogoutRequest → 302 + onLogout", async () => {
    const { idp, onLogoutCalls } = await buildSamlIdp()
    const samlRequest = postLogoutRequest({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      nameId: "bob@corp.example",
    })
    const body = new URLSearchParams({ SAMLRequest: samlRequest })
    const res = await idp.handle(
      new Request(SLS_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }),
    )
    expect(res.status).toBe(302)
    expect((res.headers.get("location") ?? "").startsWith(SLO_URL)).toBe(true)
    expect(onLogoutCalls).toHaveLength(1)
    expect(onLogoutCalls[0]?.nameId).toBe("bob@corp.example")
  })

  test("FAIL-CLOSED: forged (wrong-key) LogoutRequest → denied, no redirect, no side effect", async () => {
    const { idp, audit, onLogoutCalls } = await buildSamlIdp()
    const q = await redirectLogoutRequest({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      nameId: "attacker@evil.example",
      wrongKey: true,
    })
    const res = await idp.handle(new Request(`${SLS_URL}?${q}`))

    expect(res.status).toBe(403)
    expect(res.headers.get("location")).toBeNull()
    // A signature that does not chain to the pinned IdP cert must NOT
    // be able to log anyone out.
    expect(onLogoutCalls).toHaveLength(0)
    expect(audit.byKind("token_revoked")).toHaveLength(0)
    expect(audit.byKind("session_logout")).toHaveLength(0)
  })

  test("replay: the same signed LogoutRequest twice → 2nd rejected, onLogout fires once", async () => {
    const { idp, onLogoutCalls } = await buildSamlIdp()
    const q = await redirectLogoutRequest({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      nameId: "carol@corp.example",
    })
    const first = await idp.handle(new Request(`${SLS_URL}?${q}`))
    const second = await idp.handle(new Request(`${SLS_URL}?${q}`))

    expect(first.status).toBe(302)
    expect(second.status).toBe(403)
    expect((await second.text()).toLowerCase()).toContain("replay")
    expect(onLogoutCalls).toHaveLength(1)
  })

  test("GATING: no idp.sloUrl → /sls is not public → cookie-gated 400, not a logout", async () => {
    const { idp, onLogoutCalls } = await buildSamlIdp({ withSlo: false })
    const q = await redirectLogoutRequest({
      idpEntityId: IDP_ENTITY,
      slsUrl: SLS_URL,
      nameId: "dave@corp.example",
    })
    const res = await idp.handle(new Request(`${SLS_URL}?${q}`))
    // Falls through to the flow-cookie gate (no cookie) → 400.
    expect(res.status).toBe(400)
    expect(res.status).not.toBe(302)
    expect(onLogoutCalls).toHaveLength(0)
  })

  test("metadata advertises SingleLogoutService (both bindings) iff SLO configured", async () => {
    const withSlo = await buildSamlIdp()
    const m1 = await withSlo.idp.handle(
      new Request(`${ISSUER}/m/${MID}/metadata`),
    )
    const b1 = await m1.text()
    expect(b1).toContain("<md:SingleLogoutService")
    expect(b1).toContain(
      'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"',
    )
    expect(b1).toContain(`Location="${SLS_URL}"`)
    // Anti-drift: the advertised SLS host is the same host as the ACS.
    expect(new URL(SLS_URL).host).toBe(
      new URL("https://idp.example/cb/corp-saml").host,
    )

    const noSlo = await buildSamlIdp({ withSlo: false })
    const m2 = await noSlo.idp.handle(
      new Request(`${ISSUER}/m/${MID}/metadata`),
    )
    expect(await m2.text()).not.toContain("SingleLogoutService")
  })
})
