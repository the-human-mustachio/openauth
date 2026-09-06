import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import {
  exchangeCode,
  hashClientSecret,
  saveEncryptedCode,
} from "../../src/domain/token"
import { refreshTokens } from "../../src/domain/refresh"
import type { CodePayload } from "../../src/types/token"
import { asTenantId } from "../../src/types/tenant"
import { buildTenant } from "../helpers/tenant"
import { testSubjects } from "../helpers/subjects"

const tenantId = asTenantId("acme")

function basePayload(): CodePayload {
  return {
    tenantId,
    clientId: "rp-1",
    appRedirectUri: "https://app.example/callback",
    appState: "rp-state",
    scopes: ["openid"],
    audience: undefined,
    clientPkce: undefined,
    methodId: "stub",
    methodKind: "stub",
    context: null,
    providerSubject: "ps-1",
    properties: { handle: "ada" },
    authTime: Math.floor(Date.now() / 1000),
    expiresAt: Date.now() + 60_000,
  }
}

async function withFixture(
  opts: { clientType?: "public" | "confidential"; secret?: string } = {},
) {
  const tenant = await buildTenant({
    methods: [{ id: "stub", kind: "stub" }],
    clientType: opts.clientType ?? "public",
    clientSecretPlain: opts.secret,
  })
  let now = 1_000
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

describe("exchangeCode: happy path", () => {
  test("issues access + refresh, audits token_issued", async () => {
    const f = await withFixture()
    const payload = basePayload()
    await saveEncryptedCode("code-1", payload, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-1",
        clientId: "rp-1",
        redirectUri: payload.appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        subjects: testSubjects,
        success: async ({ providerSubject }) =>
          ({
            type: "user",
            properties: { userId: providerSubject },
          }) as never,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.access_token.split(".").length).toBe(3) // JWT
      expect(r.value.refresh_token).toBeDefined()
      expect(r.value.token_type).toBe("Bearer")
    }
    expect(f.auditLog.byKind("token_issued").length).toBe(1)
  })
})

describe("exchangeCode: failure paths", () => {
  test("rejects already-consumed code", async () => {
    const f = await withFixture()
    await saveEncryptedCode("code-2", basePayload(), 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    await f.tokenStore.consumeCode("code-2") // consume once
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-2",
        clientId: "rp-1",
        redirectUri: basePayload().appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => ({ type: "user", properties: {} }) as never,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_grant")
  })

  test("rejects client_id mismatch", async () => {
    const f = await withFixture()
    await saveEncryptedCode("code-3", basePayload(), 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-3",
        clientId: "wrong-rp",
        redirectUri: basePayload().appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => ({ type: "user", properties: {} }) as never,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_grant")
  })

  test("rejects redirect_uri mismatch", async () => {
    const f = await withFixture()
    await saveEncryptedCode("code-4", basePayload(), 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-4",
        clientId: "rp-1",
        redirectUri: "https://evil/cb",
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => ({ type: "user", properties: {} }) as never,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
  })

  test("PKCE missing verifier fails", async () => {
    const f = await withFixture()
    const payload = basePayload()
    payload.clientPkce = { challenge: "ch", method: "S256" }
    await saveEncryptedCode("code-5", payload, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-5",
        clientId: "rp-1",
        redirectUri: payload.appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => ({ type: "user", properties: {} }) as never,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.description).toContain("code_verifier")
  })

  test("confidential client missing secret fails", async () => {
    const f = await withFixture({
      clientType: "confidential",
      secret: "topsecret",
    })
    await saveEncryptedCode("code-6", basePayload(), 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-6",
        clientId: "rp-1",
        redirectUri: basePayload().appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => ({ type: "user", properties: {} }) as never,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_client")
  })

  test("confidential client with wrong secret fails", async () => {
    const f = await withFixture({
      clientType: "confidential",
      secret: "topsecret",
    })
    await saveEncryptedCode("code-7", basePayload(), 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-7",
        clientId: "rp-1",
        clientSecret: "wrong",
        redirectUri: basePayload().appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => ({ type: "user", properties: {} }) as never,
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
  })

  test("success callback throw → server_error", async () => {
    const f = await withFixture()
    await saveEncryptedCode("code-8", basePayload(), 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const r = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "code-8",
        clientId: "rp-1",
        redirectUri: basePayload().appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () => {
          throw new Error("boom")
        },
        issuerUrl: "https://idp.example",
        clock: () => 1,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("server_error")
  })
})

describe("hashClientSecret", () => {
  test("is deterministic and produces base64url", async () => {
    const a = await hashClientSecret("secret")
    const b = await hashClientSecret("secret")
    expect(a).toBe(b)
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})

describe("refreshTokens: rotation", () => {
  test("rotates the token; second use of old token detects reuse", async () => {
    const f = await withFixture()
    const payload = basePayload()
    await saveEncryptedCode("c", payload, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })

    const issued = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "c",
        clientId: "rp-1",
        redirectUri: payload.appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () =>
          ({ type: "user", properties: { id: "u1" } }) as never,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    if (!issued.ok) throw new Error("issue failed")
    const firstRefresh = issued.value.refresh_token!

    // First rotation succeeds, returns a new refresh token.
    f.setClock(2_000)
    const r1 = await refreshTokens(
      { grantType: "refresh_token", refreshToken: firstRefresh },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    expect(r1.ok).toBe(true)
    if (!r1.ok) return
    expect(r1.value.refresh_token).not.toBe(firstRefresh)
    expect(f.auditLog.byKind("token_refreshed").length).toBe(1)

    // Second use of the original token triggers reuse detection.
    f.setClock(3_000)
    const r2 = await refreshTokens(
      { grantType: "refresh_token", refreshToken: firstRefresh },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    expect(r2.ok).toBe(false)
    expect(f.auditLog.byKind("refresh_reuse_detected").length).toBe(1)
  })

  test("requested scope cannot exceed original grant", async () => {
    const f = await withFixture()
    const payload = basePayload()
    payload.scopes = ["openid", "email"]
    await saveEncryptedCode("c", payload, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const issued = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "c",
        clientId: "rp-1",
        redirectUri: payload.appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () =>
          ({ type: "user", properties: { id: "u1" } }) as never,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    if (!issued.ok) throw new Error("issue failed")
    f.setClock(2_000)
    const r = await refreshTokens(
      {
        grantType: "refresh_token",
        refreshToken: issued.value.refresh_token!,
        scope: "openid email admin", // admin not granted originally
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("invalid_scope")
  })

  test("an invalid_scope request leaves the refresh token usable", async () => {
    // The scope check runs against the peeked grant, before the token is
    // consumed -- same rule the client-auth and DPoP gates above follow.
    // Consuming first would let a client typo burn the token, so the next
    // legitimate refresh would return invalid_grant with a reuse signal
    // and could revoke the entire family.
    const f = await withFixture()
    const payload = basePayload()
    payload.scopes = ["openid", "email"]
    await saveEncryptedCode("c", payload, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const issued = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "c",
        clientId: "rp-1",
        redirectUri: payload.appRedirectUri,
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        subjects: testSubjects,
        success: async () =>
          ({ type: "user", properties: { id: "u1" } }) as never,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    if (!issued.ok) throw new Error("issue failed")
    const refresh = issued.value.refresh_token!

    const deps = {
      configStore: f.configStore,
      tokenStore: f.tokenStore,
      keyStore: f.keyStore,
      auditLog: f.auditLog,
      issuerUrl: "https://idp.example",
      clock: f.clock,
    }

    f.setClock(2_000)
    const typo = await refreshTokens(
      {
        grantType: "refresh_token",
        refreshToken: refresh,
        scope: "openid admin",
      },
      deps,
    )
    expect(typo.ok).toBe(false)
    if (!typo.ok) expect(typo.error.code).toBe("invalid_scope")

    // The same token must still work. Before the fix this returned
    // invalid_grant, because the failed request had already consumed it.
    f.setClock(3_000)
    const retry = await refreshTokens(
      { grantType: "refresh_token", refreshToken: refresh },
      deps,
    )
    expect(retry.ok).toBe(true)
    if (!retry.ok) throw new Error(`retry failed: ${retry.error.code}`)
    expect(retry.value.access_token).toBeTruthy()

    // And no reuse alarm was raised by the legitimate retry.
    expect(f.auditLog.byKind("refresh_reuse_detected").length).toBe(0)
  })
})
