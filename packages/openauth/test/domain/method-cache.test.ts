import { describe, expect, test } from "bun:test"

import { MemoryAuditLog } from "../../src/adapters/memory"
import { MethodCache } from "../../src/domain/method-cache"
import { brokenIdFactory, inlineSuccessFactory } from "../helpers/method"
import { buildTenant } from "../helpers/tenant"

describe("MethodCache", () => {
  test("resolves a configured method and caches the build", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "stub-1", kind: "stub" }],
    })
    const cache = new MethodCache({
      factories: { stub: inlineSuccessFactory({ kind: "stub" }) },
      now: () => 1,
    })
    const r1 = await cache.resolve(tenant, "stub-1")
    expect(r1.ok).toBe(true)
    const r2 = await cache.resolve(tenant, "stub-1")
    expect(r2.ok).toBe(true)
    if (r1.ok && r2.ok) expect(r1.value).toBe(r2.value)
  })

  test("returns method_not_found for unknown methodId", async () => {
    const tenant = await buildTenant()
    const cache = new MethodCache({
      factories: { stub: inlineSuccessFactory({ kind: "stub" }) },
      now: () => 1,
    })
    const r = await cache.resolve(tenant, "missing")
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.code).toBe("method_not_found")
  })

  test("audits unknown_method_kind when no factory matches", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "weird", kind: "missing-factory" }],
    })
    const audit = new MemoryAuditLog()
    const cache = new MethodCache({
      factories: { stub: inlineSuccessFactory({ kind: "stub" }) },
      auditLog: audit,
      now: () => 1,
    })
    const r = await cache.resolve(tenant, "weird")
    expect(r.ok).toBe(false)
    expect(audit.byKind("unknown_method_kind").length).toBe(1)
  })

  test("audits factory_id_mismatch when factory build returns wrong id/kind", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "broken", kind: "broken-factory" }],
    })
    const audit = new MemoryAuditLog()
    const cache = new MethodCache({
      factories: { "broken-factory": brokenIdFactory("broken-factory") },
      auditLog: audit,
      now: () => 1,
    })
    const r = await cache.resolve(tenant, "broken")
    expect(r.ok).toBe(false)
    expect(audit.byKind("factory_id_mismatch").length).toBe(1)
  })

  test("invalidate drops cached entry", async () => {
    const tenant = await buildTenant({ methods: [{ id: "x", kind: "stub" }] })
    const cache = new MethodCache({
      factories: { stub: inlineSuccessFactory({ kind: "stub" }) },
      now: () => 1,
    })
    const r1 = await cache.resolve(tenant, "x")
    cache.invalidate(tenant.id, "x")
    const r2 = await cache.resolve(tenant, "x")
    expect(r1.ok && r2.ok && r1.value !== r2.value).toBe(true)
  })
})
