import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { handleCallback } from "../../src/domain/callback"
import { MethodCache } from "../../src/domain/method-cache"
import { mintStateEnvelope } from "../../src/domain/state-envelope"
import { startAuthorize } from "../../src/domain/authorize"
import type { AuthorizationRequest } from "../../src/types/authorization"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant, tenantContextFor } from "../helpers/tenant"

async function fixture() {
  const tenant = await buildTenant({
    methods: [{ id: "stub", kind: "stub" }],
  })
  const now = Date.now()
  let clockValue = now
  const clock = () => clockValue
  const setClock = (v: number) => {
    clockValue = v
  }
  const configStore = new MemoryConfigStore({ seed: [tenant] })
  const sessionStore = new MemorySessionStore({ clock })
  const keyStore = new MemoryKeyStore({ clock })
  const tokenStore = new MemoryTokenStore({ keyStore, clock })
  const auditLog = new MemoryAuditLog()
  const methodCache = new MethodCache({
    factories: { stub: redirectFactory({ kind: "stub" }) as never },
    auditLog,
    now: clock,
  })
  return {
    tenant,
    configStore,
    sessionStore,
    keyStore,
    tokenStore,
    auditLog,
    methodCache,
    stateKeys: buildStateKeys(),
    clock,
    setClock,
  }
}

function authorizeRequest(
  opts: Partial<AuthorizationRequest> = {},
): AuthorizationRequest {
  return {
    tenantId: "acme" as never,
    clientId: "rp-1",
    redirectUri: "https://app.example/callback",
    responseType: "code",
    scopes: ["openid"],
    state: "rp-state",
    codeChallenge: "dGVzdGNoYWxsZW5nZXRlc3RjaGFsbGVuZ2V0ZXN0Y2hhbGw",
    codeChallengeMethod: "S256",
    ...opts,
  }
}

describe("handleCallback: state verification", () => {
  test("rejects missing state", async () => {
    const f = await fixture()
    const r = await handleCallback(
      {
        rawRequest: new Request("https://idp.example/cb/stub"),
        cookies: new Map(),
      },
      {
        configStore: f.configStore,
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        auditLog: f.auditLog,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_request")
  })

  test("rejects state signed by an unknown key", async () => {
    const f = await fixture()
    const otherRing = buildStateKeys(99)
    const state = await mintStateEnvelope(
      { tenantId: f.tenant.id, flowId: "fake", nonce: "n" },
      otherRing,
    )
    const r = await handleCallback(
      {
        rawRequest: new Request(
          `https://idp.example/cb/stub?state=${encodeURIComponent(state)}`,
        ),
        cookies: new Map(),
      },
      {
        configStore: f.configStore,
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        auditLog: f.auditLog,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(false)
    expect(f.auditLog.byKind("flow_replay_attempt").length).toBe(1)
  })
})

describe("handleCallback: full authorize → callback", () => {
  test("happy path issues a code", async () => {
    const f = await fixture()

    // 1. /authorize creates the flow + state.
    const authorize = await startAuthorize(
      {
        request: authorizeRequest(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    if (!authorize.ok) throw new Error("authorize failed")
    if (authorize.value.kind !== "challenge") {
      throw new Error(`expected challenge, got ${authorize.value.kind}`)
    }

    // 2. Extract the state from the method's upstream redirect.
    const location = authorize.value.response.headers.get("location")!
    const upstreamUrl = new URL(location)
    const state = upstreamUrl.searchParams.get("state")!

    // 3. Simulate the upstream redirecting back to the callback URL.
    const r = await handleCallback(
      {
        rawRequest: new Request(
          `https://idp.example/cb/stub?state=${encodeURIComponent(state)}&code=upstream-code`,
        ),
        cookies: new Map(),
      },
      {
        configStore: f.configStore,
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        auditLog: f.auditLog,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok && r.value.kind === "issue-code") {
      expect(r.value.code.length).toBeGreaterThan(20)
      expect(r.value.appRedirectUri).toBe("https://app.example/callback")
      expect(r.value.appState).toBe("rp-state")
    } else {
      throw new Error("expected issue-code")
    }
  })

  test("second callback presentation rejects (flow consumed)", async () => {
    const f = await fixture()
    const authorize = await startAuthorize(
      {
        request: authorizeRequest(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    if (!authorize.ok || authorize.value.kind !== "challenge")
      throw new Error("auth")
    const location = authorize.value.response.headers.get("location")!
    const upstreamUrl = new URL(location)
    const state = upstreamUrl.searchParams.get("state")!

    const url = `https://idp.example/cb/stub?state=${encodeURIComponent(state)}&code=u`
    const deps = {
      configStore: f.configStore,
      sessionStore: f.sessionStore,
      tokenStore: f.tokenStore,
      auditLog: f.auditLog,
      methodCache: f.methodCache,
      stateKeys: f.stateKeys,
      clock: f.clock,
    }
    const first = await handleCallback(
      { rawRequest: new Request(url), cookies: new Map() },
      deps,
    )
    expect(first.ok).toBe(true)
    const second = await handleCallback(
      { rawRequest: new Request(url), cookies: new Map() },
      deps,
    )
    expect(second.ok).toBe(false)
    expect(f.auditLog.byKind("flow_replay_attempt").length).toBeGreaterThan(0)
  })

  test("host mismatch is rejected with audit", async () => {
    const f = await fixture()
    const authorize = await startAuthorize(
      {
        request: authorizeRequest(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    if (!authorize.ok || authorize.value.kind !== "challenge")
      throw new Error("auth")
    const location = authorize.value.response.headers.get("location")!
    const state = new URL(location).searchParams.get("state")!

    const r = await handleCallback(
      {
        rawRequest: new Request(
          // Wrong host:
          `https://wrong.example/cb/stub?state=${encodeURIComponent(state)}`,
        ),
        cookies: new Map(),
      },
      {
        configStore: f.configStore,
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        auditLog: f.auditLog,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(false)
    expect(f.auditLog.byKind("flow_callback_mismatch").length).toBe(1)
  })
})
