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
          expect(peek.value.methodState).toEqual({ upstreamPkceVerifier: "v-1" })
        }
        const consumed = await store.consumeFlow(flow.flowId)
        expect(consumed.ok).toBe(true)
        if (consumed.ok) {
          expect(consumed.value.methodState).toEqual({ upstreamPkceVerifier: "v-1" })
        }
      })

      test("updateFlowMethodState on unknown flow returns unknown_state", async () => {
        const result = await store.updateFlowMethodState(uniqueSuffix("missing"), {})
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
        const result = await store.saveFlow(
          uniqueSuffix("f"),
          makeFlow(),
          0,
        )
        expect(result.ok).toBe(false)
      })
    })

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
          const saved = await store.createSession(id, record, 24 * 60 * 60 * 1000)
          expect(saved.ok).toBe(true)
          const read = await store.readSession(id)
          expect(read.ok).toBe(true)
          if (read.ok) {
            expect(read.value.subjectId).toBe("u1")
          }
        })

        test("revokeSession removes the session", async () => {
          if (!store.createSession || !store.readSession || !store.revokeSession) return
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
