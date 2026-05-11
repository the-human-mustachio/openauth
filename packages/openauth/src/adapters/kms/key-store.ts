/**
 * KMS-backed `KeyStore`.
 *
 * Envelope encryption: generate a JWK key pair (or AES key) locally, wrap
 * the private material with AWS KMS `Encrypt`, store the ciphertext in the
 * supplied `KmsBackingStore`. On read, unwrap with KMS `Decrypt` and
 * `importJWK` so the framework receives a normal `CryptoKey` for JWT signing
 * — no surgery in `domain/jwt.ts`.
 *
 * Hot-path KMS calls are cached: signing keys are imported once per
 * `kid` and re-used (a `CryptoKey` is safe to share across signs). Encryption
 * keys are cached in plaintext bytes per `kid` so `consumeCode` doesn't make
 * a KMS call per request.
 *
 * Operators with strict no-cache-of-plaintext requirements can disable the
 * cache via `cacheUnwrappedKeys: false` — every read then round-trips to
 * KMS.
 */
import type { JWK } from "jose"
import { exportJWK, generateKeyPair, importJWK } from "jose"

import { generateSymmetricKey, randomId, utf8 } from "../../domain/crypto"
import type { EncryptionKey, KeyStore, SigningKey } from "../../ports/key-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type {
  KmsBackingStore,
  KmsClientLike,
  WrappedEncryptionKey,
  WrappedSigningKey,
} from "./types"

export type KmsKeyStoreOptions = {
  kms: KmsClientLike
  backing: KmsBackingStore
  clock?: () => number
  signingAlg?: "ES256" | "EdDSA"
  /** Default `true`. Set false for strict no-plaintext-cache deployments. */
  cacheUnwrappedKeys?: boolean
}

export class KmsKeyStore implements KeyStore {
  #kms: KmsClientLike
  #backing: KmsBackingStore
  #clock: () => number
  #signingAlg: "ES256" | "EdDSA"
  #cacheUnwrapped: boolean
  #signingCache = new Map<string, unknown>()
  #encryptionCache = new Map<string, Uint8Array>()

  constructor(opts: KmsKeyStoreOptions) {
    this.#kms = opts.kms
    this.#backing = opts.backing
    this.#clock = opts.clock ?? (() => Date.now())
    this.#signingAlg = opts.signingAlg ?? "ES256"
    this.#cacheUnwrapped = opts.cacheUnwrappedKeys ?? true
  }

  async currentSigningKey(): Promise<Result<SigningKey>> {
    await this.#ensureSigningKey()
    const all = await this.#backing.listSigningKeys()
    const active = all.find((k) => k.status === "active")
    if (!active) {
      return err(
        authError.internalError("no active signing key (should be unreachable)"),
      )
    }
    return ok(await this.#hydrateSigning(active))
  }

  async signingKeys(): Promise<Result<SigningKey[]>> {
    await this.#ensureSigningKey()
    const all = await this.#backing.listSigningKeys()
    const keys = await Promise.all(all.map((row) => this.#hydrateSigning(row)))
    return ok(keys)
  }

  async currentEncryptionKey(): Promise<Result<EncryptionKey>> {
    await this.#ensureEncryptionKey()
    const all = await this.#backing.listEncryptionKeys()
    const active = all.find((k) => k.status === "active")
    if (!active) {
      return err(
        authError.internalError(
          "no active encryption key (should be unreachable)",
        ),
      )
    }
    return ok(await this.#hydrateEncryption(active))
  }

  async getEncryptionKey(kid: string): Promise<Result<EncryptionKey>> {
    const row = await this.#backing.getEncryptionKey(kid)
    if (!row) {
      return err(authError.internalError(`encryption key "${kid}" not found`))
    }
    return ok(await this.#hydrateEncryption(row))
  }

  async #ensureSigningKey(): Promise<void> {
    const all = await this.#backing.listSigningKeys()
    if (all.some((k) => k.status === "active")) return
    const { publicKey, privateKey } = await generateKeyPair(this.#signingAlg, {
      extractable: true,
    })
    const publicJwk = await exportJWK(publicKey)
    const privateJwk = await exportJWK(privateKey)
    const plaintext = utf8.encode(JSON.stringify(privateJwk))
    const wrapped = await this.#kms.encrypt(plaintext)
    const row: WrappedSigningKey = {
      kid: randomId(),
      alg: this.#signingAlg,
      ...(publicJwk.crv ? { crv: publicJwk.crv } : {}),
      publicJwk: publicJwk as unknown as Record<string, unknown>,
      wrappedPrivate: wrapped,
      status: "active",
      createdAt: this.#clock(),
    }
    await this.#backing.putSigningKey(row)
  }

  async #ensureEncryptionKey(): Promise<void> {
    const all = await this.#backing.listEncryptionKeys()
    if (all.some((k) => k.status === "active")) return
    const raw = generateSymmetricKey()
    const wrapped = await this.#kms.encrypt(raw)
    const row: WrappedEncryptionKey = {
      kid: randomId(),
      alg: "A256GCM",
      wrappedKey: wrapped,
      status: "active",
      createdAt: this.#clock(),
    }
    await this.#backing.putEncryptionKey(row)
  }

  async #hydrateSigning(row: WrappedSigningKey): Promise<SigningKey> {
    let imported = this.#signingCache.get(row.kid)
    if (!imported) {
      const plaintext = await this.#kms.decrypt(row.wrappedPrivate)
      const jwk = JSON.parse(utf8.decode(plaintext)) as JWK
      imported = await importJWK(jwk, row.alg)
      if (this.#cacheUnwrapped) this.#signingCache.set(row.kid, imported)
    }
    return {
      kid: row.kid,
      alg: row.alg,
      ...(row.crv ? { crv: row.crv } : {}),
      publicJwk: row.publicJwk,
      privateKeyRef: imported,
      status: row.status,
      createdAt: row.createdAt,
      ...(row.rotatedAt !== undefined ? { rotatedAt: row.rotatedAt } : {}),
    }
  }

  async #hydrateEncryption(row: WrappedEncryptionKey): Promise<EncryptionKey> {
    let bytes = this.#encryptionCache.get(row.kid)
    if (!bytes) {
      bytes = await this.#kms.decrypt(row.wrappedKey)
      if (this.#cacheUnwrapped) this.#encryptionCache.set(row.kid, bytes)
    }
    return {
      kid: row.kid,
      alg: row.alg,
      keyRef: bytes,
      status: row.status,
      createdAt: row.createdAt,
      ...(row.rotatedAt !== undefined ? { rotatedAt: row.rotatedAt } : {}),
    }
  }
}
