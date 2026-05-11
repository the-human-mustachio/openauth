/**
 * Parameterized `TokenStore` conformance suite.
 *
 * Adapters opt in by exporting a `makeStore` factory (and a matching
 * `makeKeyStore` for the encryption-at-rest path) and calling
 * `describeTokenStore({ adapterName, makeStore, makeKeyStore, inspectRawCode })`
 * from their own test file. Any adapter that fails a case here is not
 * certified per `ports/CONSISTENCY.md`.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { KeyStore } from "../../src/ports/key-store"
import type { TokenStore } from "../../src/ports/token-store"

import {
  fixtureTenantId,
  makeCodePayload,
  makeRefreshPayload,
  testClock,
  uniqueSuffix,
  type TestClock,
} from "./fixtures"

export type TokenStoreSuiteOptions = {
  adapterName: string
  /**
   * Build a fresh `TokenStore` + matching `KeyStore` per test.
   *
   * `inspectRawCode(code)` returns ANY string snapshot of the at-rest
   * representation of the given auth-code row so the suite can assert it
   * does NOT contain a plaintext canary. Adapter-specific because adapters
   * persist as JWE strings in a column, JSON blobs, opaque object handles,
   * etc.
   */
  makeStore: (clock: TestClock) => Promise<{
    tokenStore: TokenStore
    keyStore: KeyStore
    inspectRawCode: (code: string) => Promise<string>
    /** Optional teardown — close pools, drop tables, etc. */
    dispose?: () => Promise<void>
  }>
}

export function describeTokenStore(opts: TokenStoreSuiteOptions): void {
  describe(`TokenStore conformance — ${opts.adapterName}`, () => {
    let clock: TestClock
    let tokenStore: TokenStore
    let keyStore: KeyStore
    let inspectRawCode: (code: string) => Promise<string>
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      clock = testClock()
      const built = await opts.makeStore(clock)
      tokenStore = built.tokenStore
      keyStore = built.keyStore
      inspectRawCode = built.inspectRawCode
      dispose = built.dispose
      // Force the key store to materialize an encryption key so the assertion
      // about encryption-at-rest does not race a lazy-init code path.
      await keyStore.currentEncryptionKey()
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    describe("saveCode / consumeCode", () => {
      test("round-trips a payload encrypted at rest", async () => {
        const code = uniqueSuffix("code")
        const payload = makeCodePayload({
          providerSubject: "PLAINTEXT-CANARY-12345",
        })
        const saved = await tokenStore.saveCode(code, payload, 60_000)
        expect(saved.ok).toBe(true)

        const rawSnapshot = await inspectRawCode(code)
        expect(rawSnapshot).not.toContain("PLAINTEXT-CANARY-12345")
        expect(rawSnapshot).not.toContain(payload.appRedirectUri)

        const consumed = await tokenStore.consumeCode(code)
        expect(consumed.ok).toBe(true)
        if (!consumed.ok) return
        expect(consumed.value.providerSubject).toBe("PLAINTEXT-CANARY-12345")
        expect(consumed.value.tenantId).toBe(fixtureTenantId)
      })

      test("second consume returns invalid_grant (single-use)", async () => {
        const code = uniqueSuffix("code")
        await tokenStore.saveCode(code, makeCodePayload(), 60_000)
        const first = await tokenStore.consumeCode(code)
        expect(first.ok).toBe(true)
        const second = await tokenStore.consumeCode(code)
        expect(second.ok).toBe(false)
        if (!second.ok) expect(second.error.code).toBe("invalid_grant")
      })

      test("concurrent consume resolves to exactly one winner", async () => {
        const code = uniqueSuffix("code")
        await tokenStore.saveCode(code, makeCodePayload(), 60_000)
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
        const result = await tokenStore.saveCode(code, makeCodePayload(), 60_001)
        expect(result.ok).toBe(false)
      })

      test("rejects ttl <= 0", async () => {
        const code = uniqueSuffix("code")
        const zero = await tokenStore.saveCode(code, makeCodePayload(), 0)
        expect(zero.ok).toBe(false)
        const neg = await tokenStore.saveCode(code, makeCodePayload(), -1)
        expect(neg.ok).toBe(false)
      })

      test("expired codes are not returned", async () => {
        const code = uniqueSuffix("code")
        await tokenStore.saveCode(code, makeCodePayload(), 30_000)
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
      test("first consume returns payload; second within window flags reuse with family", async () => {
        const refresh = uniqueSuffix("r")
        const payload = makeRefreshPayload({ family: "FAM-X" })
        await tokenStore.saveRefresh(refresh, payload)
        const first = await tokenStore.consumeRefresh(refresh)
        expect(first.ok).toBe(true)
        const second = await tokenStore.consumeRefresh(refresh)
        expect(second.ok).toBe(false)
        if (!second.ok) {
          expect(second.error.code).toBe("invalid_grant")
          // Reuse-detection wire format documented in Phase 2 decisions —
          // adapters MUST emit `family=...,tenant=...,subject=...`.
          expect(second.error.description).toContain("reuse detected")
          expect(second.error.description).toContain("family=FAM-X")
          expect(second.error.description).toContain(`tenant=${fixtureTenantId}`)
          expect(second.error.description).toContain("subject=subj-1")
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
