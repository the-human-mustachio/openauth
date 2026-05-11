/**
 * In-memory `KeyStore`. Auto-generates ES256 signing keys and A256GCM
 * encryption keys on first read. Suitable for tests and single-instance
 * dev.
 */
import { exportJWK, generateKeyPair } from "jose"

import type { EncryptionKey, KeyStore, SigningKey } from "../../ports/key-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import { generateSymmetricKey, randomId } from "../../domain/crypto"
import type { Clock } from "./clock"
import { realClock } from "./clock"

export type MemoryKeyStoreOptions = {
  clock?: Clock
  /** Override default `"ES256"` (other supported: `"EdDSA"` per AD11). */
  signingAlg?: "ES256" | "EdDSA"
}

export class MemoryKeyStore implements KeyStore {
  #clock: Clock
  #signingAlg: "ES256" | "EdDSA"
  #signing: SigningKey[] = []
  #encryption: EncryptionKey[] = []

  constructor(opts: MemoryKeyStoreOptions = {}) {
    this.#clock = opts.clock ?? realClock
    this.#signingAlg = opts.signingAlg ?? "ES256"
  }

  async currentSigningKey(): Promise<Result<SigningKey>> {
    await this.#ensureSigningKey()
    const active = this.#signing.find((k) => k.status === "active")
    if (!active) {
      return err(
        authError.internalError(
          "no active signing key (should be unreachable)",
        ),
      )
    }
    return ok(active)
  }

  async signingKeys(): Promise<Result<SigningKey[]>> {
    await this.#ensureSigningKey()
    return ok([...this.#signing])
  }

  async currentEncryptionKey(): Promise<Result<EncryptionKey>> {
    this.#ensureEncryptionKey()
    const active = this.#encryption.find((k) => k.status === "active")
    if (!active) {
      return err(
        authError.internalError(
          "no active encryption key (should be unreachable)",
        ),
      )
    }
    return ok(active)
  }

  async getEncryptionKey(kid: string): Promise<Result<EncryptionKey>> {
    this.#ensureEncryptionKey()
    const match = this.#encryption.find((k) => k.kid === kid)
    if (!match) {
      return err(authError.internalError(`encryption key "${kid}" not found`))
    }
    return ok(match)
  }

  async #ensureSigningKey(): Promise<void> {
    if (this.#signing.some((k) => k.status === "active")) return
    const { publicKey, privateKey } = await generateKeyPair(this.#signingAlg, {
      extractable: true,
    })
    const jwk = await exportJWK(publicKey)
    const key: SigningKey = {
      kid: randomId(),
      alg: this.#signingAlg,
      crv: jwk.crv ?? undefined,
      publicJwk: jwk as unknown as Record<string, unknown>,
      privateKeyRef: privateKey,
      status: "active",
      createdAt: this.#clock(),
    }
    this.#signing.push(key)
  }

  #ensureEncryptionKey(): void {
    if (this.#encryption.some((k) => k.status === "active")) return
    const key: EncryptionKey = {
      kid: randomId(),
      alg: "A256GCM",
      keyRef: generateSymmetricKey(),
      status: "active",
      createdAt: this.#clock(),
    }
    this.#encryption.push(key)
  }
}
