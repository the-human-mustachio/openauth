/**
 * Parameterized `ConfigStore` conformance suite.
 *
 * Covers `putTenantConfig` / `getTenantConfig` round-trip, missing-tenant
 * lookup, and the invalidation hook firing on write.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { ConfigStore } from "../../src/ports/config-store"
import { asTenantId } from "../../src/types/tenant"

import { makeTenantConfig, uniqueSuffix } from "./fixtures"

export type ConfigStoreSuiteOptions = {
  adapterName: string
  makeStore: () => Promise<{
    store: ConfigStore
    dispose?: () => Promise<void>
  }>
}

export function describeConfigStore(opts: ConfigStoreSuiteOptions): void {
  describe(`ConfigStore conformance — ${opts.adapterName}`, () => {
    let store: ConfigStore
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      const built = await opts.makeStore()
      store = built.store
      dispose = built.dispose
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    test("putTenantConfig + getTenantConfig round-trips", async () => {
      const id = asTenantId(uniqueSuffix("tenant"))
      const cfg = makeTenantConfig({ id, displayName: "Round-trip" })
      const put = await store.putTenantConfig(cfg)
      expect(put.ok).toBe(true)
      const got = await store.getTenantConfig(id)
      expect(got.ok).toBe(true)
      if (got.ok) {
        expect(got.value.displayName).toBe("Round-trip")
        expect(got.value.clients.length).toBeGreaterThan(0)
      }
    })

    test("getTenantConfig(unknown) returns tenant_not_found", async () => {
      const got = await store.getTenantConfig(asTenantId(uniqueSuffix("missing")))
      expect(got.ok).toBe(false)
      if (!got.ok) expect(got.error.code).toBe("tenant_not_found")
    })

    test("invalidation hook fires on putTenantConfig (when supported)", async () => {
      if (!store.onInvalidate) return
      const id = asTenantId(uniqueSuffix("tenant"))
      const cfg = makeTenantConfig({ id })
      let count = 0
      const seen: string[] = []
      store.onInvalidate((tid) => {
        count += 1
        seen.push(tid as string)
      })
      await store.putTenantConfig(cfg)
      expect(count).toBeGreaterThanOrEqual(1)
      expect(seen[seen.length - 1]).toBe(id as string)
    })

    test("update replaces previous value", async () => {
      const id = asTenantId(uniqueSuffix("tenant"))
      await store.putTenantConfig(makeTenantConfig({ id, displayName: "v1" }))
      await store.putTenantConfig(makeTenantConfig({ id, displayName: "v2" }))
      const got = await store.getTenantConfig(id)
      expect(got.ok).toBe(true)
      if (got.ok) expect(got.value.displayName).toBe("v2")
    })
  })
}
