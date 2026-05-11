/**
 * Parameterized `KeyStore` conformance suite.
 *
 * Covers signing-key + encryption-key invariants per `ports/CONSISTENCY.md`:
 *  - `currentSigningKey` / `currentEncryptionKey` strongly consistent
 *  - `signingKeys()` (JWKS feed) includes the active key
 *  - `getEncryptionKey(kid)` round-trips after `currentEncryptionKey`
 *  - JWK contains required public-material fields
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { KeyStore } from "../../src/ports/key-store"

import { testClock, type TestClock } from "./fixtures"

export type KeyStoreSuiteOptions = {
  adapterName: string
  makeStore: (clock: TestClock) => Promise<{
    store: KeyStore
    dispose?: () => Promise<void>
  }>
}

export function describeKeyStore(opts: KeyStoreSuiteOptions): void {
  describe(`KeyStore conformance — ${opts.adapterName}`, () => {
    let clock: TestClock
    let store: KeyStore
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

    test("currentSigningKey returns a key with a kid + alg + public JWK", async () => {
      const result = await store.currentSigningKey()
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(typeof result.value.kid).toBe("string")
      expect(result.value.kid.length).toBeGreaterThan(0)
      expect(["ES256", "EdDSA"]).toContain(result.value.alg)
      expect(result.value.publicJwk).toBeDefined()
      expect(result.value.status).toBe("active")
    })

    test("currentSigningKey is unambiguous across repeated reads", async () => {
      const a = await store.currentSigningKey()
      const b = await store.currentSigningKey()
      expect(a.ok && b.ok).toBe(true)
      if (a.ok && b.ok) expect(a.value.kid).toBe(b.value.kid)
    })

    test("signingKeys() contains the active key", async () => {
      const cur = await store.currentSigningKey()
      const all = await store.signingKeys()
      expect(all.ok).toBe(true)
      if (!cur.ok || !all.ok) return
      const kids = all.value.map((k) => k.kid)
      expect(kids).toContain(cur.value.kid)
    })

    test("currentEncryptionKey + getEncryptionKey round-trip", async () => {
      const cur = await store.currentEncryptionKey()
      expect(cur.ok).toBe(true)
      if (!cur.ok) return
      expect(cur.value.alg).toBe("A256GCM")
      const looked = await store.getEncryptionKey(cur.value.kid)
      expect(looked.ok).toBe(true)
      if (looked.ok) expect(looked.value.kid).toBe(cur.value.kid)
    })

    test("getEncryptionKey(unknown kid) errors", async () => {
      const result = await store.getEncryptionKey("kid-does-not-exist")
      expect(result.ok).toBe(false)
    })
  })
}
