/**
 * `KeyStore` — signing keys (JWT) and encryption keys (auth-code payload,
 * other at-rest secrets).
 *
 * Per AD11, ES256 is the default signing algorithm; Ed25519 is supported.
 *
 * Consistency:
 *  - `currentSigningKey` — strong (active key must be unambiguous across
 *    the cluster).
 *  - `signingKeys` (JWKS) — eventual OK; verifiers tolerate brief lag
 *    during rotation.
 *  - Encryption keys — same as signing for consistency; rotated quarterly,
 *    old keys retained for `refreshTtl`.
 *
 * Note: `StateKeyRing` (HMAC keys for the `state` envelope) is **not** an
 * abstraction over `KeyStore`. It is supplied directly via
 * `IdPOptions.stateKeys` to avoid a bootstrap dependency on `KeyStore` for
 * tenant resolution. A helper `loadStateKeyRingFromKeyStore` is offered
 * for operators who choose to store the ring inside `KeyStore`.
 */
import type { Result } from "../types/result.js"

/** Asymmetric signing key. Public material is JWKS-exposed; private is server-only. */
export type SigningKey = {
  kid: string
  /** JOSE `alg` value, e.g. `"ES256"` or `"EdDSA"`. */
  alg: string
  /** JOSE `crv` for EC / OKP keys (`P-256`, `Ed25519`). Optional for other alg families. */
  crv?: string
  /** JWK form of the public key — published in JWKS. */
  publicJwk: Record<string, unknown>
  /**
   * Opaque private-key handle. Concrete adapters interpret this:
   *  - In-memory / Postgres: a serialized JWK.
   *  - KMS-backed: a KMS key ARN / Cloudflare DO id.
   */
  privateKeyRef: unknown
  /** Status used by JWKS rotation logic. */
  status: "active" | "next" | "retired"
  createdAt: number
  /** When this key may no longer be used to sign. Verification continues until removal. */
  rotatedAt?: number
}

/** Symmetric encryption key for the auth-code payload (and other at-rest data). */
export type EncryptionKey = {
  kid: string
  /** JOSE `alg`, e.g. `"A256GCM"`. */
  alg: string
  /** Opaque key handle (raw bytes for in-memory; KMS ref for cloud). */
  keyRef: unknown
  status: "active" | "next" | "retired"
  createdAt: number
  rotatedAt?: number
}

export type KeyStore = {
  /** The unambiguous active signing key. Strong consistency. */
  currentSigningKey(): Promise<Result<SigningKey>>

  /**
   * All keys to publish in JWKS — active + recently rotated, within the
   * verification overlap window. Eventual consistency acceptable.
   */
  signingKeys(): Promise<Result<SigningKey[]>>

  /** Active encryption key for at-rest payload encryption. Strong consistency. */
  currentEncryptionKey(): Promise<Result<EncryptionKey>>

  /**
   * Look up a specific encryption key by `kid`. Used to decrypt payloads
   * encrypted under a previous key during the overlap window.
   */
  getEncryptionKey(kid: string): Promise<Result<EncryptionKey>>

  /**
   * Rotate signing keys — promote `next` → `active`, retire current
   * `active`, mint a new `next`. Phase 8 schedules this on a timer.
   */
  rotateSigningKeys?(): Promise<Result<void>>

  /** Same as `rotateSigningKeys` for encryption keys. Quarterly cadence. */
  rotateEncryptionKeys?(): Promise<Result<void>>
}
