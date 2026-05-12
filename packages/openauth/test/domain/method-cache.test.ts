import { describe, expect, test } from "bun:test"
import { z } from "zod"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { MethodCache } from "../../src/domain/method-cache"
import { err, ok } from "../../src/types/result"
import { authError } from "../../src/types/error"
import type { ConfigStore } from "../../src/ports/config-store"
import type { TenantId } from "../../src/types/tenant"
import { buildStateKeys } from "../helpers/state-keys"
import type {
  AuthMethod,
  AuthMethodFactory,
} from "../../src/types/method"
import { brokenIdFactory, inlineSuccessFactory } from "../helpers/method"
import { buildTenant } from "../helpers/tenant"

/**
 * Factory that records every build's `tag` on a shared `builds` array so
 * tests can assert which config a cached method was last rebuilt from.
 */
function taggedFactory(builds: string[]): AuthMethodFactory<
  { tag: string },
  unknown,
  { tag: string }
> {
  return {
    kind: "tagged",
    configSchema: z.object({ tag: z.string() }),
    build: async ({
      id,
      kind,
      config,
    }): Promise<AuthMethod<{ tag: string }, unknown>> => {
      builds.push(config.tag)
      return {
        id,
        kind,
        type: "custom",
        routes: {},
      }
    },
  }
}

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

  test("createIdP registers an onInvalidate listener on the ConfigStore (H7)", async () => {
    const tenant = await buildTenant({ methods: [{ id: "stub", kind: "stub" }] })
    const listeners: Array<(id: TenantId) => void> = []
    const wrappedConfigStore: ConfigStore = {
      async getTenantConfig(id) {
        if (id === tenant.id) return ok(tenant)
        return err(authError.tenantNotFound("", id))
      },
      async putTenantConfig() {
        return ok(undefined)
      },
      onInvalidate(handler) {
        listeners.push(handler)
      },
    }
    createIdP({
      resolveTenant: async () => ok(tenant.id),
      stateKeys: buildStateKeys(),
      configStore: wrappedConfigStore,
      tokenStore: new MemoryTokenStore({
        keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
        clock: () => Date.now(),
      }),
      sessionStore: new MemorySessionStore({ clock: () => Date.now() }),
      keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
      issuerUrl: "https://idp.example",
      methods: { stub: inlineSuccessFactory({ kind: "stub" }) as never },
      subjects: {} as never,
      success: async () => ({ type: "x", properties: {} }) as never,
    })
    expect(listeners.length).toBe(1)
    // Invoking the listener does not throw — it's the MethodCache.invalidate
    // hook the framework installs.
    listeners[0]!(tenant.id)
  })

  test("ConfigStore.onInvalidate → MethodCache.invalidate picks up rotated config (H7)", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "t", kind: "tagged", config: { tag: "v1" } }],
    })
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const builds: string[] = []
    const cache = new MethodCache({
      factories: { tagged: taggedFactory(builds) },
      now: () => 1,
    })
    // Mirror createIdP's wire-up.
    configStore.onInvalidate((id) => cache.invalidate(id))

    const before = await cache.resolve(tenant, "t")
    expect(before.ok).toBe(true)
    expect(builds).toEqual(["v1"])

    // Cache hit — no rebuild yet.
    await cache.resolve(tenant, "t")
    expect(builds).toEqual(["v1"])

    // Rotate the tenant's method config. Closure-captured config from
    // the previous build would otherwise stay live forever — pre-fix the
    // upstream client_secret rotation is silently ignored.
    const rotated = {
      ...tenant,
      methods: [
        { ...tenant.methods[0]!, config: { tag: "v2" } },
      ],
    }
    await configStore.putTenantConfig(rotated)

    const after = await cache.resolve(rotated, "t")
    expect(after.ok).toBe(true)
    expect(builds).toEqual(["v1", "v2"])
    if (before.ok && after.ok) expect(before.value).not.toBe(after.value)
  })
})
