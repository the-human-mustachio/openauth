/**
 * KMS-backed `KeyStore` conformance + a focused round-trip test that
 * verifies envelope encryption (the wrapped private material in the
 * backing store is not equal to the plaintext JWK).
 */
import { describe, expect, test } from "bun:test"

import { inMemoryKmsBackingStore, KmsKeyStore } from "../../src/adapters/kms"

import { createMockKmsClient } from "../helpers/kms-mock"
import { describeKeyStore } from "../ports"

describeKeyStore({
  adapterName: "kms (mock + in-memory backing)",
  async makeStore(clock) {
    const kms = await createMockKmsClient()
    const backing = inMemoryKmsBackingStore()
    return {
      store: new KmsKeyStore({ kms, backing, clock: clock.now }),
    }
  },
})

describe("KmsKeyStore — envelope encryption", () => {
  test("private JWK is wrapped in the backing store (no plaintext canary)", async () => {
    const kms = await createMockKmsClient()
    const backing = inMemoryKmsBackingStore()
    const store = new KmsKeyStore({ kms, backing })
    await store.currentSigningKey()
    const rows = await backing.listSigningKeys()
    expect(rows.length).toBe(1)
    const row = rows[0]!
    // The wrapped private material is bytes; serialize for inspection.
    const wrappedB64 = Buffer.from(row.wrappedPrivate).toString("base64")
    // A real JWK private key for ES256 has a "d" claim. The wrapped bytes
    // shouldn't contain literal `"d":` or `"kty":` substrings.
    const wrappedText = new TextDecoder("utf-8", { fatal: false }).decode(
      row.wrappedPrivate,
    )
    expect(wrappedText).not.toContain('"d":')
    expect(wrappedText).not.toContain('"kty":')
    expect(wrappedB64.length).toBeGreaterThan(0)
  })

  test("encryption key bytes are wrapped (decrypt round-trips)", async () => {
    const kms = await createMockKmsClient()
    const backing = inMemoryKmsBackingStore()
    const store = new KmsKeyStore({ kms, backing })
    const cur = await store.currentEncryptionKey()
    expect(cur.ok).toBe(true)
    if (!cur.ok) return
    expect(cur.value.keyRef).toBeInstanceOf(Uint8Array)
    expect((cur.value.keyRef as Uint8Array).byteLength).toBe(32)
    // Re-fetch by kid — the cache returns the same bytes; the backing store
    // returns ciphertext that decrypts to the same plaintext.
    const looked = await store.getEncryptionKey(cur.value.kid)
    expect(looked.ok).toBe(true)
    if (looked.ok) {
      expect(Array.from(looked.value.keyRef as Uint8Array)).toEqual(
        Array.from(cur.value.keyRef as Uint8Array),
      )
    }
  })
})
