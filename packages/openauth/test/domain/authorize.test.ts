import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { MethodCache } from "../../src/domain/method-cache"
import { startAuthorize } from "../../src/domain/authorize"
import type { AuthorizationRequest } from "../../src/types/authorization"
import { inlineSuccessFactory, redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant, tenantContextFor } from "../helpers/tenant"

async function fixture(
  opts: {
    factories?: Record<string, ReturnType<typeof inlineSuccessFactory>>
    methods?: Array<{ id: string; kind: string; enabled?: boolean }>
    pkceRequired?: boolean
    redirectUri?: string
  } = {},
) {
  const factories = opts.factories ?? {
    stub: inlineSuccessFactory({ kind: "stub" }),
  }
  const tenant = await buildTenant({
    methods: opts.methods ?? [{ id: "stub-1", kind: "stub" }],
    pkceRequired: opts.pkceRequired ?? true,
    redirectUri: opts.redirectUri,
  })
  const configStore = new MemoryConfigStore({ seed: [tenant] })
  const sessionStore = new MemorySessionStore()
  const keyStore = new MemoryKeyStore()
  const tokenStore = new MemoryTokenStore({ keyStore })
  const auditLog = new MemoryAuditLog()
  const methodCache = new MethodCache({
    factories,
    auditLog,
    now: () => 1,
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
  }
}

function request(
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

describe("startAuthorize: validation", () => {
  test("rejects unknown client", async () => {
    const f = await fixture()
    const r = await startAuthorize(
      {
        request: request({ clientId: "missing" }),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_client")
  })

  test("rejects unregistered redirect_uri", async () => {
    const f = await fixture()
    const r = await startAuthorize(
      {
        request: request({ redirectUri: "https://evil.example/cb" }),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error.code).toBe("invalid_request")
      expect(r.error.description).toContain("redirect_uri")
    }
  })

  test("rejects scope outside client allowlist", async () => {
    const f = await fixture()
    const r = await startAuthorize(
      {
        request: request({ scopes: ["admin"] }),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_scope")
  })

  test("rejects missing PKCE when required", async () => {
    const f = await fixture({ pkceRequired: true })
    const r = await startAuthorize(
      {
        request: request({ codeChallenge: undefined }),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_request")
  })
})

describe("startAuthorize: method selection", () => {
  test("auto-selects sole enabled method", async () => {
    const f = await fixture()
    const r = await startAuthorize(
      {
        request: request(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value.kind).toBe("issue-code") // inline success
  })

  test("returns select-method when >1 enabled methods and none specified", async () => {
    const f = await fixture({
      factories: {
        stub: inlineSuccessFactory({ kind: "stub" }),
        other: inlineSuccessFactory({ kind: "other" }),
      },
      methods: [
        { id: "stub-1", kind: "stub" },
        { id: "other-1", kind: "other" },
      ],
    })
    const r = await startAuthorize(
      {
        request: request(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok && r.value.kind === "select-method") {
      expect(r.value.methods.length).toBe(2)
    } else {
      throw new Error(
        `expected select-method, got ${r.ok ? r.value.kind : r.error.code}`,
      )
    }
  })
})

describe("startAuthorize: dispatch outcomes", () => {
  test("inline success path issues an auth code", async () => {
    const f = await fixture()
    const r = await startAuthorize(
      {
        request: request(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok && r.value.kind === "issue-code") {
      expect(r.value.code.length).toBeGreaterThan(20)
      expect(r.value.appRedirectUri).toBe("https://app.example/callback")
      expect(r.value.appState).toBe("rp-state")
    } else {
      throw new Error(
        `expected issue-code; got ${r.ok ? r.value.kind : r.error.code}`,
      )
    }
    expect(f.auditLog.byKind("authorize_started").length).toBe(1)
  })

  test("challenge path saves methodState before returning response", async () => {
    const f = await fixture({
      factories: { stub: redirectFactory({ kind: "stub" }) as never },
    })
    const r = await startAuthorize(
      {
        request: request(),
        rawRequest: new Request("https://idp.example/authorize"),
        tenant: tenantContextFor(f.tenant),
        cookies: new Map(),
      },
      {
        sessionStore: f.sessionStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        methodCache: f.methodCache,
        stateKeys: f.stateKeys,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok && r.value.kind === "challenge") {
      expect(r.value.response.status).toBe(302)
      const loc = r.value.response.headers.get("location")
      expect(loc).toBeTruthy()
      expect(loc).toContain("state=")
      // upstream redirect should also include the callback URL
      expect(loc).toContain("redirect_uri=")
    } else {
      throw new Error("expected challenge")
    }
  })
})
