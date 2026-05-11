import { beforeEach, describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import type { CodePayload, RefreshTokenPayload } from "../../src/types/token"
import type { FlowRecord } from "../../src/types/flow"
import { asTenantId } from "../../src/types/tenant"

const tenantId = asTenantId("acme")

function makeCodePayload(): CodePayload {
  return {
    tenantId,
    clientId: "rp-1",
    appRedirectUri: "https://app/cb",
    appState: "rp-state",
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

function makeRefreshPayload(): RefreshTokenPayload {
  return {
    tenantId,
    clientId: "rp-1",
    subjectId: "subj-1",
    claim: {
      type: "user",
      properties: { userId: "u1" },
    } as RefreshTokenPayload["claim"],
    scopes: ["openid"],
    family: "fam-1",
    issuedAt: Date.now(),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
  }
}

function makeFlow(): FlowRecord {
  return {
    flowId: "f-1",
    tenantId,
    methodId: "stub",
    methodKind: "stub",
    clientId: "rp-1",
    appRedirectUri: "https://app/cb",
    callbackPath: "/cb/stub",
    callbackHost: "idp.example",
    appState: null,
    scopes: ["openid"],
    responseType: "code",
    nonce: "n-1",
    methodState: null,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000,
  }
}

describe("MemoryTokenStore", () => {
  let keyStore: MemoryKeyStore
  let tokenStore: MemoryTokenStore

  beforeEach(() => {
    keyStore = new MemoryKeyStore()
    tokenStore = new MemoryTokenStore({ keyStore })
  })

  test("saveCode encrypts at rest — internal map contains no plaintext", async () => {
    const payload = makeCodePayload()
    payload.providerSubject = "PLAINTEXT-CANARY"
    const saved = await tokenStore.saveCode("code-1", payload, 60_000)
    expect(saved.ok).toBe(true)
    // Reach into the private map via JSON inspection of the instance.
    const internal = JSON.stringify(tokenStore)
    expect(internal).not.toContain("PLAINTEXT-CANARY")
  })

  test("consumeCode returns decrypted payload, then errors on second call", async () => {
    const payload = makeCodePayload()
    await tokenStore.saveCode("code-2", payload, 60_000)
    const first = await tokenStore.consumeCode("code-2")
    expect(first.ok).toBe(true)
    if (!first.ok) return
    expect(first.value.providerSubject).toBe(payload.providerSubject)
    const second = await tokenStore.consumeCode("code-2")
    expect(second.ok).toBe(false)
  })

  test("saveCode rejects ttl > 60s", async () => {
    const payload = makeCodePayload()
    const result = await tokenStore.saveCode("code-3", payload, 61_000)
    expect(result.ok).toBe(false)
  })

  test("consumeRefresh first use succeeds; second use within window triggers reuse signal", async () => {
    const refresh = "refresh-1"
    await tokenStore.saveRefresh(refresh, makeRefreshPayload())
    const first = await tokenStore.consumeRefresh(refresh)
    expect(first.ok).toBe(true)
    const second = await tokenStore.consumeRefresh(refresh)
    expect(second.ok).toBe(false)
    if (!second.ok) {
      expect(second.error.description).toContain("reuse detected")
      expect(second.error.description).toContain("family=fam-1")
    }
  })

  test("reuse detection revokes whole family", async () => {
    const r1 = "refresh-a"
    const r2 = "refresh-b"
    const p1 = makeRefreshPayload()
    const p2 = { ...makeRefreshPayload(), family: p1.family }
    await tokenStore.saveRefresh(r1, p1)
    await tokenStore.saveRefresh(r2, p2)
    // Consume r1 once OK, twice triggers family revoke.
    await tokenStore.consumeRefresh(r1)
    await tokenStore.consumeRefresh(r1)
    // Now r2 (same family) should also be gone.
    const r2Use = await tokenStore.consumeRefresh(r2)
    expect(r2Use.ok).toBe(false)
  })

  test("revokeBySubject removes all refresh tokens for that subject", async () => {
    await tokenStore.saveRefresh("ra", makeRefreshPayload())
    await tokenStore.saveRefresh("rb", makeRefreshPayload())
    const r = await tokenStore.revokeBySubject(tenantId, "subj-1")
    expect(r.ok).toBe(true)
    expect((await tokenStore.consumeRefresh("ra")).ok).toBe(false)
    expect((await tokenStore.consumeRefresh("rb")).ok).toBe(false)
  })
})

describe("MemorySessionStore", () => {
  test("saveFlow + consumeFlow returns the full record once", async () => {
    const store = new MemorySessionStore()
    const flow = makeFlow()
    await store.saveFlow(flow.flowId, flow, 10_000)
    const first = await store.consumeFlow(flow.flowId)
    expect(first.ok).toBe(true)
    if (!first.ok) return
    expect(first.value.flowId).toBe(flow.flowId)
    expect(first.value.tenantId).toBe(flow.tenantId)
    const second = await store.consumeFlow(flow.flowId)
    expect(second.ok).toBe(false)
  })

  test("updateFlowMethodState merges atomically before consume", async () => {
    const store = new MemorySessionStore()
    const flow = makeFlow()
    await store.saveFlow(flow.flowId, flow, 10_000)
    await store.updateFlowMethodState(flow.flowId, { upstreamNonce: "x" })
    const consumed = await store.consumeFlow(flow.flowId)
    expect(consumed.ok).toBe(true)
    if (!consumed.ok) return
    expect(consumed.value.methodState).toEqual({ upstreamNonce: "x" })
  })

  test("consumeFlow errors after expiry", async () => {
    let now = 0
    const store = new MemorySessionStore({ clock: () => now })
    const flow = makeFlow()
    await store.saveFlow(flow.flowId, flow, 1000)
    now = 2000
    const consumed = await store.consumeFlow(flow.flowId)
    expect(consumed.ok).toBe(false)
  })
})

describe("MemoryConfigStore", () => {
  test("put then get round-trips; invalidation hook fires", async () => {
    const store = new MemoryConfigStore()
    const tenantConfig = {
      id: tenantId,
      displayName: "Acme",
      clients: [],
      methods: [],
    }
    let invalidations = 0
    store.onInvalidate(() => invalidations++)
    await store.putTenantConfig(tenantConfig)
    expect(invalidations).toBe(1)
    const got = await store.getTenantConfig(tenantId)
    expect(got.ok).toBe(true)
    if (got.ok) expect(got.value.displayName).toBe("Acme")
  })

  test("getTenantConfig returns tenant_not_found for unknown id", async () => {
    const store = new MemoryConfigStore()
    const got = await store.getTenantConfig(asTenantId("missing"))
    expect(got.ok).toBe(false)
    if (!got.ok) expect(got.error.code).toBe("tenant_not_found")
  })
})

describe("MemoryKeyStore", () => {
  test("auto-generates signing key on first read; signing keys list is non-empty", async () => {
    const ks = new MemoryKeyStore()
    const cur = await ks.currentSigningKey()
    expect(cur.ok).toBe(true)
    const all = await ks.signingKeys()
    expect(all.ok).toBe(true)
    if (all.ok) expect(all.value.length).toBeGreaterThan(0)
  })

  test("encryption key roundtrip via getEncryptionKey", async () => {
    const ks = new MemoryKeyStore()
    const cur = await ks.currentEncryptionKey()
    expect(cur.ok).toBe(true)
    if (!cur.ok) return
    const looked = await ks.getEncryptionKey(cur.value.kid)
    expect(looked.ok).toBe(true)
  })
})

describe("MemoryAuditLog", () => {
  test("byKind filter returns matching events", async () => {
    const log = new MemoryAuditLog()
    await log.log({
      kind: "authorize_started",
      tenantId,
      clientId: "rp",
      methodId: "m",
      methodKind: "k",
      flowId: "f",
      timestamp: 1,
    })
    await log.log({
      kind: "token_issued",
      tenantId,
      clientId: "rp",
      methodId: "m",
      methodKind: "k",
      subjectId: "s",
      timestamp: 2,
    })
    expect(log.byKind("authorize_started").length).toBe(1)
    expect(log.byKind("token_issued").length).toBe(1)
    expect(log.byKind("refresh_reuse_detected").length).toBe(0)
  })
})
