/**
 * DynamoDB `KeyStore`. Single-table — signing keys under `pk="signing-key"`,
 * encryption keys under `pk="encryption-key"`. Private JWKs are stored as
 * JSON strings; encryption key material as base64url. Auto-generates an
 * active key pair on first read.
 */
import type { JWK } from "jose"
import { exportJWK, generateKeyPair, importJWK } from "jose"

import {
  base64url,
  generateSymmetricKey,
  randomId,
} from "../../domain/crypto"
import type { EncryptionKey, KeyStore, SigningKey } from "../../ports/key-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type { DynamoExecutor } from "./client"

export type DynamoKeyStoreOptions = {
  exec: DynamoExecutor
  clock?: () => number
  signingAlg?: "ES256" | "EdDSA"
}

export class DynamoKeyStore implements KeyStore {
  #exec: DynamoExecutor
  #clock: () => number
  #signingAlg: "ES256" | "EdDSA"
  #privateKeyCache = new Map<string, unknown>()

  constructor(opts: DynamoKeyStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
    this.#signingAlg = opts.signingAlg ?? "ES256"
  }

  async currentSigningKey(): Promise<Result<SigningKey>> {
    await this.#ensureSigningKey()
    const items = await this.#exec.query({
      pk: "signing-key",
      consistentRead: true,
      filter: { attribute: "status", equals: "active" },
    })
    const row = items[0]
    if (!row) {
      return err(
        authError.internalError("no active signing key (should be unreachable)"),
      )
    }
    return ok(await this.#hydrateSigning(row))
  }

  async signingKeys(): Promise<Result<SigningKey[]>> {
    await this.#ensureSigningKey()
    const items = await this.#exec.query({
      pk: "signing-key",
      consistentRead: false,
    })
    const keys = await Promise.all(items.map((r) => this.#hydrateSigning(r)))
    return ok(keys)
  }

  async currentEncryptionKey(): Promise<Result<EncryptionKey>> {
    await this.#ensureEncryptionKey()
    const items = await this.#exec.query({
      pk: "encryption-key",
      consistentRead: true,
      filter: { attribute: "status", equals: "active" },
    })
    const row = items[0]
    if (!row) {
      return err(
        authError.internalError(
          "no active encryption key (should be unreachable)",
        ),
      )
    }
    return ok(this.#hydrateEncryption(row))
  }

  async getEncryptionKey(kid: string): Promise<Result<EncryptionKey>> {
    const row = await this.#exec.get({
      key: { pk: "encryption-key", sk: kid },
      consistentRead: true,
    })
    if (!row) {
      return err(authError.internalError(`encryption key "${kid}" not found`))
    }
    return ok(this.#hydrateEncryption(row))
  }

  async #ensureSigningKey(): Promise<void> {
    const items = await this.#exec.query({
      pk: "signing-key",
      consistentRead: true,
      filter: { attribute: "status", equals: "active" },
    })
    if (items.length > 0) return
    const { publicKey, privateKey } = await generateKeyPair(this.#signingAlg, {
      extractable: true,
    })
    const publicJwk = await exportJWK(publicKey)
    const privateJwk = await exportJWK(privateKey)
    const kid = randomId()
    try {
      await this.#exec.put({
        item: {
          pk: "signing-key",
          sk: kid,
          alg: this.#signingAlg,
          crv: publicJwk.crv ?? null,
          public_jwk: JSON.stringify(publicJwk),
          private_jwk: JSON.stringify(privateJwk),
          status: "active",
          created_at: this.#clock(),
        },
        condition: "not-exists",
      })
    } catch {
      // Lost a race against another instance — fine; their key now exists.
    }
  }

  async #ensureEncryptionKey(): Promise<void> {
    const items = await this.#exec.query({
      pk: "encryption-key",
      consistentRead: true,
      filter: { attribute: "status", equals: "active" },
    })
    if (items.length > 0) return
    const kid = randomId()
    const keyMaterial = generateSymmetricKey()
    try {
      await this.#exec.put({
        item: {
          pk: "encryption-key",
          sk: kid,
          alg: "A256GCM",
          // DynamoDB stores bytes as Buffer/Uint8Array; base64url-encoded
          // string is portable, supports `aws-sdk-client-mock`, and is
          // marshalled back the same way.
          key_material: base64url.encode(keyMaterial),
          status: "active",
          created_at: this.#clock(),
        },
        condition: "not-exists",
      })
    } catch {}
  }

  async #hydrateSigning(row: Record<string, unknown>): Promise<SigningKey> {
    const kid = String(row.sk)
    let imported = this.#privateKeyCache.get(kid)
    if (!imported) {
      const privateJwk = JSON.parse(String(row.private_jwk)) as JWK
      imported = await importJWK(privateJwk, String(row.alg))
      this.#privateKeyCache.set(kid, imported)
    }
    const publicJwk = JSON.parse(String(row.public_jwk)) as Record<string, unknown>
    return {
      kid,
      alg: String(row.alg),
      ...(row.crv ? { crv: String(row.crv) } : {}),
      publicJwk,
      privateKeyRef: imported,
      status: String(row.status) as SigningKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== undefined && row.rotated_at !== null
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }

  #hydrateEncryption(row: Record<string, unknown>): EncryptionKey {
    return {
      kid: String(row.sk),
      alg: String(row.alg),
      keyRef: base64url.decode(String(row.key_material)),
      status: String(row.status) as EncryptionKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== undefined && row.rotated_at !== null
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }
}
