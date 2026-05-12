/**
 * Mock KMS client for the KMS adapter conformance test.
 *
 * Uses a per-instance random AES-256-GCM key as the simulated master key.
 * `encrypt` AES-GCM encrypts; `decrypt` AES-GCM decrypts. The mock is good
 * enough to exercise the envelope-encryption code path end-to-end — the
 * adapter's contract is independent of the specific KMS implementation.
 */
import type { KmsClientLike } from "../../src/adapters/kms"

const { subtle } = crypto

export async function createMockKmsClient(): Promise<KmsClientLike> {
  const raw = new Uint8Array(32)
  crypto.getRandomValues(raw)
  const key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ])
  return {
    async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
      const iv = new Uint8Array(12)
      crypto.getRandomValues(iv)
      const ct = new Uint8Array(
        await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
      )
      // Frame as iv || ct.
      const out = new Uint8Array(iv.length + ct.length)
      out.set(iv, 0)
      out.set(ct, iv.length)
      return out
    },
    async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
      const iv = ciphertext.slice(0, 12)
      const ct = ciphertext.slice(12)
      const pt = new Uint8Array(
        await subtle.decrypt({ name: "AES-GCM", iv }, key, ct),
      )
      return pt
    },
  }
}
