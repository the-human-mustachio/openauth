import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { exchangeCode, saveEncryptedCode } from "../../src/domain/token"
import { revokeAllForSubject, revokeToken } from "../../src/domain/revoke"
import { introspect } from "../../src/domain/introspect"
import { userinfo } from "../../src/domain/userinfo"
import { buildDiscoveryDocument, buildJwks } from "../../src/domain/discovery"
import { asTenantId } from "../../src/types/tenant"
import type { CodePayload } from "../../src/types/token"
import { buildTenant } from "../helpers/tenant"

const tenantId = asTenantId("acme")

function basePayload(): CodePayload {
  return {
    tenantId,
    clientId: "rp-1",
    appRedirectUri: "https://app.example/callback",
    appState: null,
    scopes: ["openid"],
    audience: undefined,
    clientPkce: undefined,
    methodId: "stub",
    methodKind: "stub",
    context: null,
    providerSubject: "ps-1",
    properties: { handle: "ada" },
    expiresAt: Date.now() + 60_000,
  }
}

async function fixture() {
  const tenant = await buildTenant({
    methods: [{ id: "stub", kind: "stub" }],
  })
  // Start clock at real-time so issued JWT expiry compares sanely against
  // jose's `jwtVerify` (which uses real `Date.now()`).
  let now = Date.now()
  const clock = () => now
  const setClock = (t: number) => {
    now = t
  }
  const configStore = new MemoryConfigStore({ seed: [tenant] })
  const keyStore = new MemoryKeyStore({ clock })
  const tokenStore = new MemoryTokenStore({ keyStore, clock })
  const auditLog = new MemoryAuditLog()
  return {
    tenant,
    configStore,
    keyStore,
    tokenStore,
    auditLog,
    clock,
    setClock,
  }
}

async function issueTokens(f: Awaited<ReturnType<typeof fixture>>) {
  await saveEncryptedCode("c", basePayload(), 60_000, {
    keyStore: f.keyStore,
    tokenStore: f.tokenStore,
  })
  const r = await exchangeCode(
    {
      grantType: "authorization_code",
      code: "c",
      clientId: "rp-1",
      redirectUri: basePayload().appRedirectUri,
    },
    {
      configStore: f.configStore,
      tokenStore: f.tokenStore,
      keyStore: f.keyStore,
      success: async () =>
        ({
          type: "user",
          properties: { userId: "u1", email: "ada@example.com" },
        }) as never,
      issuerUrl: "https://idp.example",
      clock: f.clock,
    },
  )
  if (!r.ok) throw new Error("issue failed")
  return r.value
}

describe("revoke", () => {
  test("revoking a known refresh token succeeds and audits", async () => {
    const f = await fixture()
    const tokens = await issueTokens(f)
    const r = await revokeToken(
      { token: tokens.refresh_token!, tokenTypeHint: "refresh_token" },
      {
        tokenStore: f.tokenStore,
        configStore: f.configStore,
        auditLog: f.auditLog,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(true)
    expect(f.auditLog.byKind("token_revoked").length).toBe(1)
  })

  test("revoking an unknown token is a no-op success (RFC 7009)", async () => {
    const f = await fixture()
    const r = await revokeToken(
      { token: "definitely-not-a-token" },
      {
        tokenStore: f.tokenStore,
        configStore: f.configStore,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(true)
  })

  test("access_token hint is a no-op", async () => {
    const f = await fixture()
    const r = await revokeToken(
      { token: "abc", tokenTypeHint: "access_token" },
      {
        tokenStore: f.tokenStore,
        configStore: f.configStore,
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(true)
  })

  test("revokeAllForSubject removes all tokens for the subject", async () => {
    const f = await fixture()
    await issueTokens(f)
    // Derive the subject id by introspecting:
    const tokens = await issueTokens(f)
    const intr = await introspect(
      {
        token: tokens.access_token,
        clientId: "rp-1",
        presenterTenantId: tenantId,
      },
      { keyStore: f.keyStore, configStore: f.configStore },
    )
    if (!intr.ok || !intr.value.active) throw new Error("intr failed")
    const subjectId = intr.value.sub
    await revokeAllForSubject(tenantId, subjectId, {
      tokenStore: f.tokenStore,
      auditLog: f.auditLog,
      clock: f.clock,
    })
    // Both refresh tokens now gone:
    const reuse = await f.tokenStore.consumeRefresh(tokens.refresh_token!)
    expect(reuse.ok).toBe(false)
  })
})

describe("introspect", () => {
  test("returns active=true with claims for a freshly issued JWT", async () => {
    const f = await fixture()
    const tokens = await issueTokens(f)
    const r = await introspect(
      {
        token: tokens.access_token,
        clientId: "rp-1",
        presenterTenantId: tenantId,
      },
      {
        keyStore: f.keyStore,
        configStore: f.configStore,
        issuerUrl: "https://idp.example",
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok && r.value.active) {
      expect(r.value.tid).toBe(tenantId)
      expect(r.value.mid).toBe("stub")
      expect(r.value.scope).toBe("openid")
    }
  })

  test("returns active=false for garbage", async () => {
    const f = await fixture()
    const r = await introspect(
      {
        token: "not-a-jwt",
        clientId: "rp-1",
        presenterTenantId: tenantId,
      },
      { keyStore: f.keyStore, configStore: f.configStore },
    )
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value.active).toBe(false)
  })
})

describe("userinfo", () => {
  test("returns inlined subject claims for a valid bearer", async () => {
    const f = await fixture()
    const tokens = await issueTokens(f)
    const r = await userinfo(tokens.access_token, {
      keyStore: f.keyStore,
      issuerUrl: "https://idp.example",
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.subject_type).toBe("user")
      expect((r.value.properties as { email: string }).email).toBe(
        "ada@example.com",
      )
    }
  })

  test("rejects invalid bearer", async () => {
    const f = await fixture()
    const r = await userinfo("garbage", { keyStore: f.keyStore })
    expect(r.ok).toBe(false)
  })
})

describe("discovery", () => {
  test("builds a complete OIDC discovery document with default paths", () => {
    const doc = buildDiscoveryDocument({ issuerUrl: "https://idp.example" })
    expect(doc.issuer).toBe("https://idp.example")
    expect(doc.authorization_endpoint).toBe("https://idp.example/authorize")
    expect(doc.response_types_supported).toEqual(["code"])
    expect(doc.code_challenge_methods_supported).toEqual(["S256"])
    expect(doc.grant_types_supported).toContain("authorization_code")
    expect(doc.grant_types_supported).toContain("refresh_token")
  })

  test("applies custom path overrides", () => {
    const doc = buildDiscoveryDocument({
      issuerUrl: "https://idp.example",
      paths: { authorize: "/custom/authorize" },
    })
    expect(doc.authorization_endpoint).toBe(
      "https://idp.example/custom/authorize",
    )
  })

  test("buildJwks returns the active key", async () => {
    const ks = new MemoryKeyStore()
    const r = await buildJwks(ks)
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.keys.length).toBe(1)
      expect(r.value.keys[0]!.kid).toBeDefined()
      expect(r.value.keys[0]!.use).toBe("sig")
    }
  })
})
