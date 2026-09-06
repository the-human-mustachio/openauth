/**
 * `methodScratch` shim tests — verifies that the scoping prefix isolates
 * data between (tenantId, methodId) pairs and that adapters without the
 * optional `saveScratch` family surface a clean error rather than
 * silently no-op.
 */
import { describe, expect, test } from "bun:test"

import { MemorySessionStore } from "../../src/adapters/memory"
import { dispatchMethod } from "../../src/domain/method-dispatch"
import type { SessionStore } from "../../src/ports/session-store"
import type {
  AuthMethod,
  MethodContext,
  MethodResult,
} from "../../src/types/method"
import { err, ok, type Result } from "../../src/types/result"
import { asTenantId, type TenantContext } from "../../src/types/tenant"

import { buildTenant } from "../helpers/tenant"

type ProbeOutcome =
  | { kind: "put"; result: Result<void> }
  | { kind: "get"; result: Result<string> }
  | { kind: "delete"; result: Result<void> }

let lastOutcome: ProbeOutcome | null = null

function probeMethod(
  id: string,
  op: (ctx: MethodContext<unknown>) => Promise<ProbeOutcome>,
): AuthMethod<unknown, unknown> {
  return {
    id,
    kind: "stub",
    type: "custom",
    routes: {
      "GET /probe": async (ctx): Promise<MethodResult<unknown, unknown>> => {
        lastOutcome = await op(ctx)
        return { kind: "denied", reason: "probe-complete" }
      },
    },
  }
}

async function dispatchProbe(
  store: SessionStore,
  tenantId: string,
  method: AuthMethod<unknown, unknown>,
): Promise<void> {
  const config = await buildTenant({ id: tenantId })
  const tenant: TenantContext = {
    id: asTenantId(tenantId),
    config,
    request: {
      raw: new Request("https://idp.example/probe"),
      custom: {},
    },
  }
  lastOutcome = null
  const result = await dispatchMethod({
    method,
    route: "GET /probe",
    tenant,
    request: tenant.request.raw,
    subPath: "/probe",
    flow: null,
    cookies: new Map(),
    sessionStore: store,
    issuerUrl: "https://idp.example",
    dispatch: null,
  })
  expect(result.ok).toBe(true)
}

describe("methodScratch — scoping + isolation", () => {
  test("put / get round-trips for the same (tenant, method) pair", async () => {
    const store = new MemorySessionStore()
    const method = probeMethod("m-1", async (ctx) => ({
      kind: "put",
      result: await ctx.methodScratch.put("k1", "value-A", 60_000),
    }))
    await dispatchProbe(store, "t-1", method)
    expect(lastOutcome?.kind === "put" && lastOutcome.result.ok).toBe(true)

    const reader = probeMethod("m-1", async (ctx) => ({
      kind: "get",
      result: await ctx.methodScratch.get("k1"),
    }))
    await dispatchProbe(store, "t-1", reader)
    expect(lastOutcome?.kind === "get" && lastOutcome.result.ok).toBe(true)
    if (lastOutcome?.kind === "get" && lastOutcome.result.ok) {
      expect(lastOutcome.result.value).toBe("value-A")
    }
  })

  test("two method instances on the same tenant cannot read each other's keys", async () => {
    const store = new MemorySessionStore()
    const writer = probeMethod("m-alpha", async (ctx) => ({
      kind: "put",
      result: await ctx.methodScratch.put("shared", "alpha-data", 60_000),
    }))
    await dispatchProbe(store, "t-1", writer)

    const intruder = probeMethod("m-beta", async (ctx) => ({
      kind: "get",
      result: await ctx.methodScratch.get("shared"),
    }))
    await dispatchProbe(store, "t-1", intruder)
    expect(lastOutcome?.kind).toBe("get")
    if (lastOutcome?.kind === "get") {
      expect(lastOutcome.result.ok).toBe(false)
      if (!lastOutcome.result.ok) {
        expect(lastOutcome.result.error.code).toBe("unknown_state")
      }
    }
  })

  test("two tenants on the same method id cannot read each other's keys", async () => {
    const store = new MemorySessionStore()
    const writer = probeMethod("m-shared", async (ctx) => ({
      kind: "put",
      result: await ctx.methodScratch.put("k", "tenant-A-data", 60_000),
    }))
    await dispatchProbe(store, "t-A", writer)

    const reader = probeMethod("m-shared", async (ctx) => ({
      kind: "get",
      result: await ctx.methodScratch.get("k"),
    }))
    await dispatchProbe(store, "t-B", reader)
    expect(lastOutcome?.kind === "get" && lastOutcome.result.ok).toBe(false)
  })

  test("delete is idempotent and removes the entry", async () => {
    const store = new MemorySessionStore()
    const writer = probeMethod("m-x", async (ctx) => ({
      kind: "put",
      result: await ctx.methodScratch.put("k", "doomed", 60_000),
    }))
    await dispatchProbe(store, "t", writer)

    const deleter = probeMethod("m-x", async (ctx) => ({
      kind: "delete",
      result: await ctx.methodScratch.delete("k"),
    }))
    await dispatchProbe(store, "t", deleter)
    expect(lastOutcome?.kind === "delete" && lastOutcome.result.ok).toBe(true)

    // Second delete is still ok (idempotent).
    await dispatchProbe(store, "t", deleter)
    expect(lastOutcome?.kind === "delete" && lastOutcome.result.ok).toBe(true)

    const reader = probeMethod("m-x", async (ctx) => ({
      kind: "get",
      result: await ctx.methodScratch.get("k"),
    }))
    await dispatchProbe(store, "t", reader)
    expect(lastOutcome?.kind === "get" && lastOutcome.result.ok).toBe(false)
  })

  test("put rejects ttlMs <= 0", async () => {
    const store = new MemorySessionStore()
    const method = probeMethod("m", async (ctx) => ({
      kind: "put",
      result: await ctx.methodScratch.put("k", "v", 0),
    }))
    await dispatchProbe(store, "t", method)
    expect(lastOutcome?.kind === "put" && lastOutcome.result.ok).toBe(false)
  })
})

describe("methodScratch — unsupported adapter", () => {
  /**
   * A SessionStore that intentionally omits the optional scratch trio.
   * Only the required flow methods are implemented (with stub bodies; the
   * dispatch path under test never calls them).
   */
  const flowsOnlyStore: SessionStore = {
    saveFlow: async () => ok(undefined),
    updateFlowMethodState: async () => ok(undefined),
    readFlow: async () => err({ code: "unknown_state", description: "stub" }),
    consumeFlow: async () =>
      err({ code: "unknown_state", description: "stub" }),
  }

  test("put returns internal error mentioning saveScratch", async () => {
    const method = probeMethod("m", async (ctx) => ({
      kind: "put",
      result: await ctx.methodScratch.put("k", "v", 60_000),
    }))
    await dispatchProbe(flowsOnlyStore, "t", method)
    expect(lastOutcome?.kind === "put" && lastOutcome.result.ok).toBe(false)
    if (lastOutcome?.kind === "put" && !lastOutcome.result.ok) {
      expect(lastOutcome.result.error.description).toContain("saveScratch")
    }
  })

  test("get returns internal error mentioning readScratch", async () => {
    const method = probeMethod("m", async (ctx) => ({
      kind: "get",
      result: await ctx.methodScratch.get("k"),
    }))
    await dispatchProbe(flowsOnlyStore, "t", method)
    expect(lastOutcome?.kind === "get" && lastOutcome.result.ok).toBe(false)
    if (lastOutcome?.kind === "get" && !lastOutcome.result.ok) {
      expect(lastOutcome.result.error.description).toContain("readScratch")
    }
  })

  test("delete returns internal error mentioning deleteScratch", async () => {
    const method = probeMethod("m", async (ctx) => ({
      kind: "delete",
      result: await ctx.methodScratch.delete("k"),
    }))
    await dispatchProbe(flowsOnlyStore, "t", method)
    expect(lastOutcome?.kind === "delete" && lastOutcome.result.ok).toBe(false)
    if (lastOutcome?.kind === "delete" && !lastOutcome.result.ok) {
      expect(lastOutcome.result.error.description).toContain("deleteScratch")
    }
  })
})
