/**
 * `handlePublicMethodRoute` — the anonymous (flowless) pipeline, its
 * **fail-closed gate**, and the **privileged upstream-logout side
 * effect**.
 *
 * The HTTP layer checks `publicRoutes` before routing here, but a
 * no-auth domain entry point must not trust its caller: the gate is
 * re-enforced in the domain function. These tests assert that a route
 * NOT in the method's `publicRoutes` is refused even when the function
 * is called directly with it (i.e. simulating an HTTP-layer mistake),
 * and that a flowless route returning `success` fails loudly rather
 * than authenticating with no flow to consume.
 *
 * The second block is the Phase 3 riskiest layer: when a public route
 * returns a `challenge` carrying a verified `logout`, the framework
 * fires `IdPOptions.onLogout` and — only if the host names a subject —
 * revokes that subject's tokens, then returns the protocol
 * `LogoutResponse`. A throwing hook or a failed revoke must fail closed
 * (withhold the `LogoutResponse`), and a plain `challenge` (no
 * `logout`) must never touch the hook or the token store.
 */
import { describe, expect, test } from "bun:test"

import { MemoryAuditLog, MemorySessionStore } from "../../src/adapters/memory"
import {
  handlePublicMethodRoute,
  type HandlePublicMethodRouteDeps,
} from "../../src/domain/method-route"
import { samlSpFactory } from "../../src/methods/saml-sp/factory"
import type { SamlSpConfig } from "../../src/methods/saml-sp/types"
import { authError } from "../../src/types/error"
import type { LogoutEventInput } from "../../src/types/idp"
import type { AnyAuthMethodFactory, AuthMethod } from "../../src/types/method"
import { err, ok } from "../../src/types/result"
import type { TokenStore } from "../../src/ports/token-store"
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

/** Records `revokeBySubject` calls; the rest of the port is unused here. */
function spyTokenStore(opts?: { failRevoke?: boolean }) {
  const calls: Array<{ tenantId: string; subjectId: string }> = []
  const ts = {
    async revokeBySubject(tenantId: string, subjectId: string) {
      calls.push({ tenantId, subjectId })
      return opts?.failRevoke
        ? err(authError.internalError("revoke boom"))
        : ok(undefined)
    },
  } as unknown as TokenStore
  return { ts, calls }
}

function baseDeps(
  extra: Partial<HandlePublicMethodRouteDeps> = {},
): HandlePublicMethodRouteDeps {
  return {
    sessionStore: new MemorySessionStore(),
    tokenStore: spyTokenStore().ts,
    clock: () => 1_700_000_000_000,
    ...extra,
  }
}

/** A synthetic public route that returns a verified-logout challenge. */
function logoutMethod(): AuthMethod {
  return {
    id: MID,
    kind: "saml-sp",
    type: "custom",
    publicRoutes: ["POST /sls"],
    routes: {
      "POST /sls": async () => ({
        kind: "challenge",
        response: new Response(null, {
          status: 302,
          headers: {
            location:
              "https://corp-idp.example/slo?SAMLResponse=base64LogoutResponse",
          },
        }),
        logout: { nameId: "user@corp.example", sessionIndex: "sess-1" },
      }),
    },
  }
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
      baseDeps(),
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
      baseDeps(),
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
      baseDeps(),
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.code).toBe("internal_error")
  })
})

describe("handlePublicMethodRoute — upstream Single Logout side effect", () => {
  const input = async () => ({
    rawRequest: new Request(`${ISSUER}/m/${MID}/sls`, { method: "POST" }),
    tenant: await tenantCtx(),
    method: logoutMethod(),
    route: "POST /sls" as const,
    subPath: "/sls",
    dispatch: DISPATCH,
  })

  test("onLogout names a subject → tokens revoked, LogoutResponse returned, audited", async () => {
    const { ts, calls } = spyTokenStore()
    const audit = new MemoryAuditLog()
    let seen: LogoutEventInput | undefined
    const r = await handlePublicMethodRoute(await input(), {
      sessionStore: new MemorySessionStore(),
      tokenStore: ts,
      clock: () => 1_700_000_000_000,
      auditLog: audit,
      onLogout: async (evt) => {
        seen = evt
        return { revokeSubject: "subj-42" }
      },
    })

    expect(r.ok).toBe(true)
    if (!r.ok) return
    // The protocol LogoutResponse is still returned to the IdP.
    expect(r.value.kind).toBe("challenge")
    if (r.value.kind !== "challenge") return
    expect(r.value.response.status).toBe(302)

    // The verified logout intent reached the host hook intact.
    expect(seen?.reason).toBe("upstream_slo")
    expect(seen?.methodId).toBe(MID)
    expect(seen?.methodKind).toBe("saml-sp")
    expect(seen?.nameId).toBe("user@corp.example")
    expect(seen?.sessionIndex).toBe("sess-1")

    // The host-named subject's tokens were revoked.
    expect(calls).toEqual([{ tenantId: TENANT, subjectId: "subj-42" }])

    // Exactly one session_logout, tagged upstream_slo.
    const ev = audit.byKind("session_logout")
    expect(ev).toHaveLength(1)
    expect(ev[0]?.via).toBe("upstream_slo")
    expect(ev[0]?.methodId).toBe(MID)
    expect(ev[0]?.subjectId).toBe("subj-42")
  })

  test("no onLogout configured → no revocation, logout still acknowledged + audited", async () => {
    const { ts, calls } = spyTokenStore()
    const audit = new MemoryAuditLog()
    const r = await handlePublicMethodRoute(await input(), {
      sessionStore: new MemorySessionStore(),
      tokenStore: ts,
      clock: () => 1_700_000_000_000,
      auditLog: audit,
    })

    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.kind).toBe("challenge")
    expect(calls).toEqual([])
    const ev = audit.byKind("session_logout")
    expect(ev).toHaveLength(1)
    expect(ev[0]?.via).toBe("upstream_slo")
    expect(ev[0]?.subjectId).toBeUndefined()
  })

  test("onLogout returns nothing → no revocation, still acknowledged", async () => {
    const { ts, calls } = spyTokenStore()
    const r = await handlePublicMethodRoute(await input(), {
      sessionStore: new MemorySessionStore(),
      tokenStore: ts,
      clock: () => 1_700_000_000_000,
      onLogout: async () => {
        /* host cleared its own session; nothing for the library to revoke */
      },
    })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.kind).toBe("challenge")
    expect(calls).toEqual([])
  })

  test("FAIL-CLOSED: onLogout throws → internal_error, LogoutResponse withheld, nothing revoked", async () => {
    const { ts, calls } = spyTokenStore()
    const audit = new MemoryAuditLog()
    const r = await handlePublicMethodRoute(await input(), {
      sessionStore: new MemorySessionStore(),
      tokenStore: ts,
      clock: () => 1_700_000_000_000,
      auditLog: audit,
      onLogout: async () => {
        throw new Error("host logout teardown blew up")
      },
    })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.code).toBe("internal_error")
    expect(calls).toEqual([])
    expect(audit.byKind("session_logout")).toHaveLength(0)
  })

  test("FAIL-CLOSED: revoke fails → error, LogoutResponse withheld, not audited as complete", async () => {
    const { ts, calls } = spyTokenStore({ failRevoke: true })
    const audit = new MemoryAuditLog()
    const r = await handlePublicMethodRoute(await input(), {
      sessionStore: new MemorySessionStore(),
      tokenStore: ts,
      clock: () => 1_700_000_000_000,
      auditLog: audit,
      onLogout: async () => ({ revokeSubject: "subj-42" }),
    })
    expect(r.ok).toBe(false)
    if (r.ok) return
    // revoke was attempted for the right subject…
    expect(calls).toEqual([{ tenantId: TENANT, subjectId: "subj-42" }])
    // …but the failure stops us from acknowledging the logout.
    expect(audit.byKind("session_logout")).toHaveLength(0)
  })

  test("a plain challenge (no logout) never touches onLogout or the token store", async () => {
    const { ts, calls } = spyTokenStore()
    let hookCalled = false
    const r = await handlePublicMethodRoute(
      {
        rawRequest: new Request(`${ISSUER}/m/${MID}/metadata`),
        tenant: await tenantCtx(),
        method: await samlMethod(),
        route: "GET /metadata",
        subPath: "/metadata",
        dispatch: DISPATCH,
      },
      {
        sessionStore: new MemorySessionStore(),
        tokenStore: ts,
        clock: () => 1_700_000_000_000,
        onLogout: async () => {
          hookCalled = true
        },
      },
    )
    expect(r.ok).toBe(true)
    expect(hookCalled).toBe(false)
    expect(calls).toEqual([])
  })
})
