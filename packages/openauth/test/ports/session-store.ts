/**
 * Parameterized `SessionStore` conformance suite.
 *
 * Adapters call `describeSessionStore({ adapterName, makeStore })` from their
 * own test file. The fixture covers flow-record lifecycle (save / read /
 * update / consume), single-use atomicity under concurrent presentation,
 * TTL enforcement, and optional long-lived session support if the adapter
 * exposes it.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { SessionRecord, SessionStore } from "../../src/ports/session-store"

import { makeFlow, testClock, uniqueSuffix, type TestClock } from "./fixtures"

export type SessionStoreSuiteOptions = {
  adapterName: string
  makeStore: (clock: TestClock) => Promise<{
    store: SessionStore
    dispose?: () => Promise<void>
  }>
  /** Some adapters (KV-style) do not implement long-lived sessions. */
  supportsLongLivedSessions?: boolean
  /** Set true when the adapter implements `savePar` / `consumePar`. */
  supportsPar?: boolean
  /**
   * Set true when the adapter implements the
   * `saveScratch` / `readScratch` / `deleteScratch` trio. Required by
   * methods that need cross-flow per-instance state (e.g. SAML SP
   * replay protection).
   */
  supportsScratch?: boolean
}

export function describeSessionStore(opts: SessionStoreSuiteOptions): void {
  describe(`SessionStore conformance — ${opts.adapterName}`, () => {
    let clock: TestClock
    let store: SessionStore
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      clock = testClock()
      const built = await opts.makeStore(clock)
      store = built.store
      dispose = built.dispose
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    describe("flow record lifecycle", () => {
      test("saveFlow + consumeFlow returns the full record once", async () => {
        const flow = makeFlow({ flowId: uniqueSuffix("f") })
        await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)
        const first = await store.consumeFlow(flow.flowId)
        expect(first.ok).toBe(true)
        if (!first.ok) return
        expect(first.value.flowId).toBe(flow.flowId)
        expect(first.value.tenantId).toBe(flow.tenantId)
        expect(first.value.methodId).toBe(flow.methodId)
        expect(first.value.callbackPath).toBe(flow.callbackPath)
        expect(first.value.scopes).toEqual(flow.scopes)
        expect(first.value.nonce).toBe(flow.nonce)
        const second = await store.consumeFlow(flow.flowId)
        expect(second.ok).toBe(false)
        if (!second.ok) expect(second.error.code).toBe("unknown_state")
      })

      test("readFlow peeks without consuming", async () => {
        const flow = makeFlow({ flowId: uniqueSuffix("f") })
        await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)
        const peek1 = await store.readFlow(flow.flowId)
        expect(peek1.ok).toBe(true)
        const peek2 = await store.readFlow(flow.flowId)
        expect(peek2.ok).toBe(true)
        const consumed = await store.consumeFlow(flow.flowId)
        expect(consumed.ok).toBe(true)
        // After consume readFlow must miss.
        const peek3 = await store.readFlow(flow.flowId)
        expect(peek3.ok).toBe(false)
      })

      test("updateFlowMethodState is observable via readFlow and consumeFlow", async () => {
        const flow = makeFlow({ flowId: uniqueSuffix("f") })
        await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)
        const updated = await store.updateFlowMethodState(flow.flowId, {
          upstreamPkceVerifier: "v-1",
        })
        expect(updated.ok).toBe(true)
        const peek = await store.readFlow(flow.flowId)
        expect(peek.ok).toBe(true)
        if (peek.ok) {
          expect(peek.value.methodState).toEqual({
            upstreamPkceVerifier: "v-1",
          })
        }
        const consumed = await store.consumeFlow(flow.flowId)
        expect(consumed.ok).toBe(true)
        if (consumed.ok) {
          expect(consumed.value.methodState).toEqual({
            upstreamPkceVerifier: "v-1",
          })
        }
      })

      test("updateFlowMethodState on unknown flow returns unknown_state", async () => {
        const result = await store.updateFlowMethodState(
          uniqueSuffix("missing"),
          {},
        )
        expect(result.ok).toBe(false)
        if (!result.ok) expect(result.error.code).toBe("unknown_state")
      })

      test("concurrent consumeFlow resolves to exactly one winner", async () => {
        const flow = makeFlow({ flowId: uniqueSuffix("f") })
        await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)
        const results = await Promise.all([
          store.consumeFlow(flow.flowId),
          store.consumeFlow(flow.flowId),
          store.consumeFlow(flow.flowId),
          store.consumeFlow(flow.flowId),
        ])
        const wins = results.filter((r) => r.ok)
        expect(wins.length).toBe(1)
      })

      test("expired flow not returned", async () => {
        const flow = makeFlow({ flowId: uniqueSuffix("f") })
        await store.saveFlow(flow.flowId, flow, 1000)
        clock.advance(2000)
        const consumed = await store.consumeFlow(flow.flowId)
        expect(consumed.ok).toBe(false)
        const peek = await store.readFlow(flow.flowId)
        expect(peek.ok).toBe(false)
      })

      test("saveFlow rejects ttl <= 0", async () => {
        const result = await store.saveFlow(uniqueSuffix("f"), makeFlow(), 0)
        expect(result.ok).toBe(false)
      })
    })

    if (opts.supportsPar) {
      describe("pushed authorization requests (RFC 9126)", () => {
        const PAR_TTL = 60_000
        test("savePar + consumePar returns the full record once", async () => {
          if (!store.savePar || !store.consumePar) return
          const uri = `urn:ietf:params:oauth:request_uri:${uniqueSuffix("u")}`
          const now = clock.now()
          const record = {
            requestUri: uri,
            params: {
              response_type: "code",
              client_id: "rp-1",
              redirect_uri: "https://app.example/cb",
              scope: "openid",
              state: "s",
            },
            clientId: "rp-1",
            issuedAt: now,
            expiresAt: now + PAR_TTL,
          }
          const saved = await store.savePar(uri, record, PAR_TTL)
          expect(saved.ok).toBe(true)
          const first = await store.consumePar(uri)
          expect(first.ok).toBe(true)
          if (first.ok) {
            expect(first.value.requestUri).toBe(uri)
            expect(first.value.clientId).toBe("rp-1")
            expect(first.value.params.scope).toBe("openid")
          }
          // One-shot — second consume must fail.
          const second = await store.consumePar(uri)
          expect(second.ok).toBe(false)
          if (!second.ok) expect(second.error.code).toBe("unknown_state")
        })

        test("consumePar on unknown uri returns unknown_state", async () => {
          if (!store.consumePar) return
          const r = await store.consumePar(
            `urn:ietf:params:oauth:request_uri:${uniqueSuffix("missing")}`,
          )
          expect(r.ok).toBe(false)
          if (!r.ok) expect(r.error.code).toBe("unknown_state")
        })

        test("expired par record not returned", async () => {
          if (!store.savePar || !store.consumePar) return
          const uri = `urn:ietf:params:oauth:request_uri:${uniqueSuffix("e")}`
          const now = clock.now()
          await store.savePar(
            uri,
            {
              requestUri: uri,
              params: {},
              clientId: "rp-1",
              issuedAt: now,
              expiresAt: now + 1000,
            },
            1000,
          )
          clock.advance(2000)
          const consumed = await store.consumePar(uri)
          expect(consumed.ok).toBe(false)
        })

        test("savePar rejects ttl <= 0", async () => {
          if (!store.savePar) return
          const uri = `urn:ietf:params:oauth:request_uri:${uniqueSuffix("0")}`
          const now = clock.now()
          const r = await store.savePar(
            uri,
            {
              requestUri: uri,
              params: {},
              clientId: "rp-1",
              issuedAt: now,
              expiresAt: now,
            },
            0,
          )
          expect(r.ok).toBe(false)
        })
      })
    }

    if (opts.supportsScratch) {
      describe("method scratch storage", () => {
        const TTL = 60_000
        test("saveScratch + readScratch round-trips", async () => {
          if (!store.saveScratch || !store.readScratch) return
          const key = `scratch:t:m:${uniqueSuffix("k")}`
          const saved = await store.saveScratch(key, "value-1", TTL)
          expect(saved.ok).toBe(true)
          const read = await store.readScratch(key)
          expect(read.ok).toBe(true)
          if (read.ok) expect(read.value).toBe("value-1")
        })

        test("saveScratch overwrites prior value for same key", async () => {
          if (!store.saveScratch || !store.readScratch) return
          const key = `scratch:t:m:${uniqueSuffix("k")}`
          await store.saveScratch(key, "v1", TTL)
          await store.saveScratch(key, "v2", TTL)
          const read = await store.readScratch(key)
          expect(read.ok).toBe(true)
          if (read.ok) expect(read.value).toBe("v2")
        })

        test("readScratch on unknown key returns unknown_state", async () => {
          if (!store.readScratch) return
          const r = await store.readScratch(
            `scratch:t:m:${uniqueSuffix("missing")}`,
          )
          expect(r.ok).toBe(false)
          if (!r.ok) expect(r.error.code).toBe("unknown_state")
        })

        test("expired scratch entry not returned", async () => {
          if (!store.saveScratch || !store.readScratch) return
          const key = `scratch:t:m:${uniqueSuffix("e")}`
          await store.saveScratch(key, "stale", 1000)
          clock.advance(2000)
          const read = await store.readScratch(key)
          expect(read.ok).toBe(false)
        })

        test("deleteScratch removes the entry and is idempotent", async () => {
          if (!store.saveScratch || !store.readScratch || !store.deleteScratch)
            return
          const key = `scratch:t:m:${uniqueSuffix("d")}`
          await store.saveScratch(key, "doomed", TTL)
          const first = await store.deleteScratch(key)
          expect(first.ok).toBe(true)
          const read = await store.readScratch(key)
          expect(read.ok).toBe(false)
          // Idempotent — second delete still resolves ok.
          const second = await store.deleteScratch(key)
          expect(second.ok).toBe(true)
        })

        test("saveScratch rejects ttlMs <= 0", async () => {
          if (!store.saveScratch) return
          const r = await store.saveScratch(
            `scratch:t:m:${uniqueSuffix("0")}`,
            "x",
            0,
          )
          expect(r.ok).toBe(false)
        })

        test("distinct keys are isolated", async () => {
          if (!store.saveScratch || !store.readScratch) return
          const a = `scratch:t:m:${uniqueSuffix("a")}`
          const b = `scratch:t:m:${uniqueSuffix("b")}`
          await store.saveScratch(a, "A", TTL)
          await store.saveScratch(b, "B", TTL)
          const ra = await store.readScratch(a)
          const rb = await store.readScratch(b)
          if (ra.ok) expect(ra.value).toBe("A")
          if (rb.ok) expect(rb.value).toBe("B")
        })
      })
    }

    if (opts.supportsLongLivedSessions) {
      describe("long-lived sessions", () => {
        test("createSession + readSession round-trips", async () => {
          if (!store.createSession || !store.readSession) return
          const id = uniqueSuffix("s")
          const record: SessionRecord = {
            sessionId: id,
            tenantId: "acme",
            subjectId: "u1",
            issuedAt: clock.now(),
            expiresAt: clock.now() + 24 * 60 * 60 * 1000,
            metadata: { ua: "test" },
          }
          const saved = await store.createSession(
            id,
            record,
            24 * 60 * 60 * 1000,
          )
          expect(saved.ok).toBe(true)
          const read = await store.readSession(id)
          expect(read.ok).toBe(true)
          if (read.ok) {
            expect(read.value.subjectId).toBe("u1")
          }
        })

        test("revokeSession removes the session", async () => {
          if (
            !store.createSession ||
            !store.readSession ||
            !store.revokeSession
          )
            return
          const id = uniqueSuffix("s")
          const record: SessionRecord = {
            sessionId: id,
            tenantId: "acme",
            subjectId: "u1",
            issuedAt: clock.now(),
            expiresAt: clock.now() + 1000,
          }
          await store.createSession(id, record, 1000)
          const revoked = await store.revokeSession(id)
          expect(revoked.ok).toBe(true)
          const read = await store.readSession(id)
          expect(read.ok).toBe(false)
        })
      })
    }
  })
}
