/**
 * Parameterized `MethodStore` conformance suite.
 *
 * Covers `putMethodConfig` / `getMethodConfig` / `listMethods` /
 * `deleteMethodConfig` and `method_not_found` semantics.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { MethodStore } from "../../src/ports/method-store"
import { asTenantId, type MethodConfig } from "../../src/types/tenant"

import { uniqueSuffix } from "./fixtures"

export type MethodStoreSuiteOptions = {
  adapterName: string
  makeStore: () => Promise<{
    store: MethodStore
    dispose?: () => Promise<void>
  }>
}

function methodConfig(overrides: Partial<MethodConfig> = {}): MethodConfig {
  return {
    id: "google-workspace",
    kind: "google",
    type: "oidc",
    enabled: true,
    config: { clientId: "abc", clientSecret: "xyz" },
    ...overrides,
  }
}

export function describeMethodStore(opts: MethodStoreSuiteOptions): void {
  describe(`MethodStore conformance — ${opts.adapterName}`, () => {
    let store: MethodStore
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      const built = await opts.makeStore()
      store = built.store
      dispose = built.dispose
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    test("put + get round-trips a method config", async () => {
      const tenantId = asTenantId(uniqueSuffix("t"))
      const m = methodConfig({ id: uniqueSuffix("m") })
      await store.putMethodConfig(tenantId, m)
      const got = await store.getMethodConfig(tenantId, m.id)
      expect(got.ok).toBe(true)
      if (got.ok) {
        expect(got.value.kind).toBe("google")
        expect(got.value.enabled).toBe(true)
      }
    })

    test("getMethodConfig(unknown) returns method_not_found", async () => {
      const tenantId = asTenantId(uniqueSuffix("t"))
      const got = await store.getMethodConfig(tenantId, uniqueSuffix("nope"))
      expect(got.ok).toBe(false)
      if (!got.ok) expect(got.error.code).toBe("method_not_found")
    })

    test("listMethods returns every method for a tenant", async () => {
      const tenantId = asTenantId(uniqueSuffix("t"))
      const m1 = methodConfig({ id: uniqueSuffix("m") })
      const m2 = methodConfig({ id: uniqueSuffix("m"), kind: "github" })
      await store.putMethodConfig(tenantId, m1)
      await store.putMethodConfig(tenantId, m2)
      const all = await store.listMethods(tenantId)
      expect(all.ok).toBe(true)
      if (all.ok) {
        const ids = all.value.map((m) => m.id).sort()
        expect(ids).toEqual([m1.id, m2.id].sort())
      }
    })

    test("listMethods scopes to tenant", async () => {
      const t1 = asTenantId(uniqueSuffix("t"))
      const t2 = asTenantId(uniqueSuffix("t"))
      await store.putMethodConfig(t1, methodConfig({ id: "only-in-t1" }))
      const list2 = await store.listMethods(t2)
      expect(list2.ok).toBe(true)
      if (list2.ok) expect(list2.value.map((m) => m.id)).not.toContain("only-in-t1")
    })

    test("deleteMethodConfig removes the entry", async () => {
      const tenantId = asTenantId(uniqueSuffix("t"))
      const m = methodConfig({ id: uniqueSuffix("m") })
      await store.putMethodConfig(tenantId, m)
      const deleted = await store.deleteMethodConfig(tenantId, m.id)
      expect(deleted.ok).toBe(true)
      const got = await store.getMethodConfig(tenantId, m.id)
      expect(got.ok).toBe(false)
    })

    test("put replaces existing config under the same id", async () => {
      const tenantId = asTenantId(uniqueSuffix("t"))
      const id = uniqueSuffix("m")
      await store.putMethodConfig(tenantId, methodConfig({ id, enabled: true }))
      await store.putMethodConfig(tenantId, methodConfig({ id, enabled: false }))
      const got = await store.getMethodConfig(tenantId, id)
      expect(got.ok).toBe(true)
      if (got.ok) expect(got.value.enabled).toBe(false)
    })
  })
}
