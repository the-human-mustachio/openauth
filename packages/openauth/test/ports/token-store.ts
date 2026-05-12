/**
 * Parameterized `TokenStore` conformance suite.
 *
 * Adapters opt in by exporting a `makeStore` factory + (optional)
 * `inspectRawCode` and calling `describeTokenStore({ ... })` from their
 * own test file. Any adapter that fails a case here is not certified
 * per `ports/CONSISTENCY.md`.
 *
 * Post-M1 the port is a ciphertext-blob KV — adapters store the
 * `saveCode(code, ciphertext, ttl)` argument verbatim and return it on
 * `consumeCode`. The domain layer (`domain/authorize.ts` →
 * `encryptPayload`) is responsible for the at-rest opacity invariant;
 * the integration test `full-flow.test.ts` exercises the
 * encrypt-then-store path end-to-end.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { KeyStore } from "../../src/ports/key-store"
import type { TokenStore } from "../../src/ports/token-store"

import {
  fixtureTenantId,
  makeRefreshPayload,
  testClock,
  uniqueSuffix,
  type TestClock,
} from "./fixtures"

export type TokenStoreSuiteOptions = {
  adapterName: string
  makeStore: (clock: TestClock) => Promise<{
    tokenStore: TokenStore
    /**
     * `keyStore` is no longer load-bearing for the port (M1 moved
     * encryption to the domain) but the suite still threads it through
     * for the few cases that exercise refresh-token persistence.
     */
    keyStore: KeyStore
    /**
     * Optional — returns the raw at-rest representation of the given
     * code row. Adapter test files can supply this to add an extra
     * assertion that the stored blob equals what was passed to
     * `saveCode` (i.e., the adapter doesn't transform the ciphertext).
     */
    inspectRawCode?: (code: string) => Promise<string>
    /** Optional teardown — close pools, drop tables, etc. */
    dispose?: () => Promise<void>
  }>
}

export function describeTokenStore(opts: TokenStoreSuiteOptions): void {
  describe(`TokenStore conformance — ${opts.adapterName}`, () => {
    let clock: TestClock
    let tokenStore: TokenStore
    let inspectRawCode: ((code: string) => Promise<string>) | undefined
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      clock = testClock()
      const built = await opts.makeStore(clock)
      tokenStore = built.tokenStore
      inspectRawCode = built.inspectRawCode
      dispose = built.dispose
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    describe("saveCode / consumeCode", () => {
      test("round-trips the stored ciphertext blob verbatim", async () => {
        const code = uniqueSuffix("code")
        const ciphertext = "OPAQUE.CIPHERTEXT.BLOB.42"
        const saved = await tokenStore.saveCode(code, ciphertext, 60_000)
        expect(saved.ok).toBe(true)

        if (inspectRawCode) {
          const raw = await inspectRawCode(code)
          expect(raw).toContain(ciphertext)
        }

        const consumed = await tokenStore.consumeCode(code)
        expect(consumed.ok).toBe(true)
        if (consumed.ok) expect(consumed.value).toBe(ciphertext)
      })

      test("second consume returns invalid_grant (single-use)", async () => {
        const code = uniqueSuffix("code")
        await tokenStore.saveCode(code, "ct-1", 60_000)
        const first = await tokenStore.consumeCode(code)
        expect(first.ok).toBe(true)
        const second = await tokenStore.consumeCode(code)
        expect(second.ok).toBe(false)
        if (!second.ok) expect(second.error.code).toBe("invalid_grant")
      })

      test("concurrent consume resolves to exactly one winner", async () => {
        const code = uniqueSuffix("code")
        await tokenStore.saveCode(code, "ct-race", 60_000)
        const results = await Promise.all([
          tokenStore.consumeCode(code),
          tokenStore.consumeCode(code),
          tokenStore.consumeCode(code),
          tokenStore.consumeCode(code),
          tokenStore.consumeCode(code),
        ])
        const wins = results.filter((r) => r.ok)
        expect(wins.length).toBe(1)
      })

      test("rejects ttl > 60s (auth-code BCP)", async () => {
        const code = uniqueSuffix("code")
        const result = await tokenStore.saveCode(code, "ct", 60_001)
        expect(result.ok).toBe(false)
      })

      test("rejects ttl <= 0", async () => {
        const code = uniqueSuffix("code")
        const zero = await tokenStore.saveCode(code, "ct", 0)
        expect(zero.ok).toBe(false)
        const neg = await tokenStore.saveCode(code, "ct", -1)
        expect(neg.ok).toBe(false)
      })

      test("expired codes are not returned", async () => {
        const code = uniqueSuffix("code")
        await tokenStore.saveCode(code, "ct-expire", 30_000)
        clock.advance(40_000)
        const consumed = await tokenStore.consumeCode(code)
        expect(consumed.ok).toBe(false)
      })

      test("consumeCode of unknown code yields invalid_grant", async () => {
        const result = await tokenStore.consumeCode(uniqueSuffix("nope"))
        expect(result.ok).toBe(false)
        if (!result.ok) expect(result.error.code).toBe("invalid_grant")
      })
    })

    describe("saveRefresh / consumeRefresh", () => {
      test("first consume returns payload; second within window flags reuse with typed reuseSignal", async () => {
        const refresh = uniqueSuffix("r")
        const payload = makeRefreshPayload({ family: "FAM-X" })
        await tokenStore.saveRefresh(refresh, payload)
        const first = await tokenStore.consumeRefresh(refresh)
        expect(first.ok).toBe(true)
        const second = await tokenStore.consumeRefresh(refresh)
        expect(second.ok).toBe(false)
        if (!second.ok && second.error.code === "invalid_grant") {
          // Description still carries a human-readable hint, but the
          // structured reuseSignal is the load-bearing contract.
          expect(second.error.description).toContain("reuse detected")
          expect(second.error.reuseSignal).toBeDefined()
          const signal = second.error.reuseSignal!
          expect(signal.family).toBe("FAM-X")
          expect(signal.tenantId).toBe(fixtureTenantId)
          expect(signal.subjectId).toBe("subj-1")
        }
      })

      test("concurrent consume of the same token resolves to one winner", async () => {
        const refresh = uniqueSuffix("r")
        await tokenStore.saveRefresh(refresh, makeRefreshPayload())
        const results = await Promise.all([
          tokenStore.consumeRefresh(refresh),
          tokenStore.consumeRefresh(refresh),
          tokenStore.consumeRefresh(refresh),
        ])
        const wins = results.filter((r) => r.ok)
        expect(wins.length).toBe(1)
      })

      test("unknown token returns invalid_grant", async () => {
        const result = await tokenStore.consumeRefresh(uniqueSuffix("r"))
        expect(result.ok).toBe(false)
        if (!result.ok) expect(result.error.code).toBe("invalid_grant")
      })

      test("expired refresh tokens are rejected", async () => {
        const refresh = uniqueSuffix("r")
        const payload = makeRefreshPayload({
          issuedAt: clock.now(),
          expiresAt: clock.now() + 1000,
        })
        await tokenStore.saveRefresh(refresh, payload)
        clock.advance(2000)
        const result = await tokenStore.consumeRefresh(refresh)
        expect(result.ok).toBe(false)
      })

      test("revokeFamily invalidates every token in the family", async () => {
        const r1 = uniqueSuffix("r")
        const r2 = uniqueSuffix("r")
        const r3 = uniqueSuffix("r")
        const p1 = makeRefreshPayload({ family: "F-1" })
        const p2 = makeRefreshPayload({ family: "F-1" })
        const p3 = makeRefreshPayload({ family: "F-2" })
        await tokenStore.saveRefresh(r1, p1)
        await tokenStore.saveRefresh(r2, p2)
        await tokenStore.saveRefresh(r3, p3)
        const revoked = await tokenStore.revokeFamily("F-1")
        expect(revoked.ok).toBe(true)
        expect((await tokenStore.consumeRefresh(r1)).ok).toBe(false)
        expect((await tokenStore.consumeRefresh(r2)).ok).toBe(false)
        // r3 (different family) survives.
        expect((await tokenStore.consumeRefresh(r3)).ok).toBe(true)
      })

      test("reuse detection auto-triggers revokeFamily", async () => {
        const r1 = uniqueSuffix("r")
        const r2 = uniqueSuffix("r")
        const p1 = makeRefreshPayload({ family: "FAM-SHARED" })
        const p2 = makeRefreshPayload({ family: "FAM-SHARED" })
        await tokenStore.saveRefresh(r1, p1)
        await tokenStore.saveRefresh(r2, p2)
        await tokenStore.consumeRefresh(r1) // legit first use
        const reuse = await tokenStore.consumeRefresh(r1) // signal reuse
        expect(reuse.ok).toBe(false)
        // Sibling in the family is gone too.
        const sibling = await tokenStore.consumeRefresh(r2)
        expect(sibling.ok).toBe(false)
      })

      test("peekRefresh returns the payload without consuming", async () => {
        const refresh = uniqueSuffix("r")
        const payload = makeRefreshPayload({ family: "PEEK-FAM" })
        await tokenStore.saveRefresh(refresh, payload)
        const peek1 = await tokenStore.peekRefresh(refresh)
        expect(peek1.ok).toBe(true)
        if (peek1.ok) {
          expect(peek1.value.family).toBe("PEEK-FAM")
          expect(peek1.value.clientId).toBe(payload.clientId)
        }
        // Peek is idempotent — second peek still returns the payload.
        const peek2 = await tokenStore.peekRefresh(refresh)
        expect(peek2.ok).toBe(true)
        // And consume still works because peek didn't mark it consumed.
        const consumed = await tokenStore.consumeRefresh(refresh)
        expect(consumed.ok).toBe(true)
      })

      test("peekRefresh on unknown token yields invalid_grant", async () => {
        const result = await tokenStore.peekRefresh(uniqueSuffix("r"))
        expect(result.ok).toBe(false)
        if (!result.ok) expect(result.error.code).toBe("invalid_grant")
      })

      test("peekRefresh on expired token yields invalid_grant", async () => {
        const refresh = uniqueSuffix("r")
        await tokenStore.saveRefresh(
          refresh,
          makeRefreshPayload({
            issuedAt: clock.now(),
            expiresAt: clock.now() + 1000,
          }),
        )
        clock.advance(2000)
        const result = await tokenStore.peekRefresh(refresh)
        expect(result.ok).toBe(false)
      })

      test("peekRefresh racing consumeRefresh: consume is the strong gate", async () => {
        // Per CONSISTENCY.md, peekRefresh is allowed to be eventually
        // consistent — it may observe the row either before or after a
        // concurrent consume lands. The atomicity guarantee lives on
        // consumeRefresh, which must still resolve to exactly one winner
        // and leave the token single-use regardless of what peek saw.
        const refresh = uniqueSuffix("r")
        await tokenStore.saveRefresh(
          refresh,
          makeRefreshPayload({ family: "RACE-FAM" }),
        )
        const [peekResult, consumeResult] = await Promise.all([
          tokenStore.peekRefresh(refresh),
          tokenStore.consumeRefresh(refresh),
        ])
        expect(consumeResult.ok).toBe(true)
        // peek may have seen the row before or after consume — both legal.
        if (peekResult.ok) {
          expect(peekResult.value.family).toBe("RACE-FAM")
        } else {
          expect(peekResult.error.code).toBe("invalid_grant")
        }
        // Single-use is unaffected by the peek/consume race.
        const second = await tokenStore.consumeRefresh(refresh)
        expect(second.ok).toBe(false)
      })

      test("revokeBySubject scoped to (tenant, subject)", async () => {
        const ra = uniqueSuffix("r")
        const rb = uniqueSuffix("r")
        const rc = uniqueSuffix("r")
        await tokenStore.saveRefresh(ra, makeRefreshPayload({ subjectId: "alice" }))
        await tokenStore.saveRefresh(rb, makeRefreshPayload({ subjectId: "alice" }))
        await tokenStore.saveRefresh(rc, makeRefreshPayload({ subjectId: "bob" }))
        const result = await tokenStore.revokeBySubject(fixtureTenantId, "alice")
        expect(result.ok).toBe(true)
        expect((await tokenStore.consumeRefresh(ra)).ok).toBe(false)
        expect((await tokenStore.consumeRefresh(rb)).ok).toBe(false)
        // Bob's refresh survives.
        expect((await tokenStore.consumeRefresh(rc)).ok).toBe(true)
      })
    })
  })
}
