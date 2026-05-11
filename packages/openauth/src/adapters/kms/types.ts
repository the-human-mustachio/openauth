/**
 * KMS adapter interfaces.
 *
 * The KMS-backed `KeyStore` uses **envelope encryption** for private key
 * material: the JWK private bytes (signing) and the raw AES key bytes
 * (encryption) are wrapped under a KMS master key. The ciphertext blob is
 * stored in a pluggable backing store; KMS Encrypt / Decrypt are the only
 * KMS operations on the hot path.
 *
 * This shape keeps private material out of plaintext at rest while
 * preserving the JWT signing path: the framework still receives a real
 * `CryptoKey` (`importJWK` of the unwrapped JWK) so `domain/jwt.ts` doesn't
 * need to know KMS exists.
 */

/** Minimal KMS surface the adapter depends on. */
export type KmsClientLike = {
  /** Encrypt up to ~4 KB of plaintext under the master key. */
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>
  /** Decrypt a previously-issued ciphertext under the master key. */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>
}

/**
 * Persistent storage for KMS-wrapped key envelopes. Adapters provide their
 * own (Postgres, DynamoDB, file), or pass `inMemoryKmsBackingStore()` for
 * tests / single-instance dev.
 *
 * `wrappedPrivate` is the KMS-wrapped private material (JWK bytes for
 * signing keys, raw AES key bytes for encryption keys). `publicJwk` is the
 * public material (never sensitive); it's kept plaintext alongside the
 * ciphertext so JWKS lookups don't need a KMS round trip.
 */
export type KmsBackingStore = {
  putSigningKey(row: WrappedSigningKey): Promise<void>
  getSigningKey(kid: string): Promise<WrappedSigningKey | undefined>
  listSigningKeys(): Promise<WrappedSigningKey[]>
  putEncryptionKey(row: WrappedEncryptionKey): Promise<void>
  getEncryptionKey(kid: string): Promise<WrappedEncryptionKey | undefined>
  listEncryptionKeys(): Promise<WrappedEncryptionKey[]>
}

export type WrappedSigningKey = {
  kid: string
  alg: string
  crv?: string
  publicJwk: Record<string, unknown>
  wrappedPrivate: Uint8Array
  status: "active" | "next" | "retired"
  createdAt: number
  rotatedAt?: number
}

export type WrappedEncryptionKey = {
  kid: string
  alg: string
  wrappedKey: Uint8Array
  status: "active" | "next" | "retired"
  createdAt: number
  rotatedAt?: number
}
