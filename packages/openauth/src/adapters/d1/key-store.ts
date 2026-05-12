/**
 * D1 `KeyStore`. JWK material persisted as JSON-in-TEXT; encryption key
 * material as BLOB. Auto-generates a signing + encryption key on first read
 * so deployments don't need a bootstrap step (production users provisioning
 * keys out-of-band see the existing rows and skip auto-gen).
 */
import type { JWK } from "jose"
import { exportJWK, generateKeyPair, importJWK } from "jose"

import { generateSymmetricKey, randomId } from "../../domain/crypto"
import type { EncryptionKey, KeyStore, SigningKey } from "../../ports/key-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import { primarySession } from "./session"
import type { AnyD1Database } from "./types"

export type D1KeyStoreOptions = {
  db: AnyD1Database
  clock?: () => number
  signingAlg?: "ES256" | "EdDSA"
}

export class D1KeyStore implements KeyStore {
  #db: AnyD1Database
  #clock: () => number
  #signingAlg: "ES256" | "EdDSA"
  #privateKeyCache = new Map<string, unknown>()

  constructor(opts: D1KeyStoreOptions) {
    this.#db = opts.db
    this.#clock = opts.clock ?? (() => Date.now())
    this.#signingAlg = opts.signingAlg ?? "ES256"
  }

  async currentSigningKey(): Promise<Result<SigningKey>> {
    await this.#ensureSigningKey()
    const row = await primarySession(this.#db)
      .prepare(
        `SELECT kid, alg, crv, public_jwk, private_jwk, status, created_at, rotated_at
           FROM openauth_signing_keys WHERE status = 'active' LIMIT 1`,
      )
      .first<SigningRow>()
    if (!row) {
      return err(
        authError.internalError(
          "no active signing key (should be unreachable)",
        ),
      )
    }
    return ok(await this.#hydrateSigning(row))
  }

  async signingKeys(): Promise<Result<SigningKey[]>> {
    await this.#ensureSigningKey()
    const result = await primarySession(this.#db)
      .prepare(
        `SELECT kid, alg, crv, public_jwk, private_jwk, status, created_at, rotated_at
           FROM openauth_signing_keys WHERE status IN ('active','next','retired')`,
      )
      .all<SigningRow>()
    const keys = await Promise.all(
      result.results.map((r) => this.#hydrateSigning(r)),
    )
    return ok(keys)
  }

  async currentEncryptionKey(): Promise<Result<EncryptionKey>> {
    await this.#ensureEncryptionKey()
    const row = await primarySession(this.#db)
      .prepare(
        `SELECT kid, alg, key_material, status, created_at, rotated_at
           FROM openauth_encryption_keys WHERE status = 'active' LIMIT 1`,
      )
      .first<EncryptionRow>()
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
    const row = await primarySession(this.#db)
      .prepare(
        `SELECT kid, alg, key_material, status, created_at, rotated_at
           FROM openauth_encryption_keys WHERE kid = ?1`,
      )
      .bind(kid)
      .first<EncryptionRow>()
    if (!row) {
      return err(authError.internalError(`encryption key "${kid}" not found`))
    }
    return ok(this.#hydrateEncryption(row))
  }

  async #ensureSigningKey(): Promise<void> {
    const existing = await primarySession(this.#db)
      .prepare(
        `SELECT 1 AS one FROM openauth_signing_keys WHERE status = 'active' LIMIT 1`,
      )
      .first<{ one: number }>()
    if (existing) return
    const { publicKey, privateKey } = await generateKeyPair(this.#signingAlg, {
      extractable: true,
    })
    const publicJwk = await exportJWK(publicKey)
    const privateJwk = await exportJWK(privateKey)
    const kid = randomId()
    await primarySession(this.#db)
      .prepare(
        `INSERT OR IGNORE INTO openauth_signing_keys
           (kid, alg, crv, public_jwk, private_jwk, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)`,
      )
      .bind(
        kid,
        this.#signingAlg,
        publicJwk.crv ?? null,
        JSON.stringify(publicJwk),
        JSON.stringify(privateJwk),
        this.#clock(),
      )
      .run()
  }

  async #ensureEncryptionKey(): Promise<void> {
    const existing = await primarySession(this.#db)
      .prepare(
        `SELECT 1 AS one FROM openauth_encryption_keys WHERE status = 'active' LIMIT 1`,
      )
      .first<{ one: number }>()
    if (existing) return
    const kid = randomId()
    const keyMaterial = generateSymmetricKey()
    await primarySession(this.#db)
      .prepare(
        `INSERT OR IGNORE INTO openauth_encryption_keys
           (kid, alg, key_material, status, created_at)
         VALUES (?1, ?2, ?3, 'active', ?4)`,
      )
      .bind(kid, "A256GCM", keyMaterial, this.#clock())
      .run()
  }

  async #hydrateSigning(row: SigningRow): Promise<SigningKey> {
    let imported = this.#privateKeyCache.get(row.kid)
    if (!imported) {
      const privateJwk = JSON.parse(row.private_jwk) as JWK
      imported = await importJWK(privateJwk, row.alg)
      this.#privateKeyCache.set(row.kid, imported)
    }
    return {
      kid: row.kid,
      alg: row.alg,
      ...(row.crv ? { crv: row.crv } : {}),
      publicJwk: JSON.parse(row.public_jwk) as Record<string, unknown>,
      privateKeyRef: imported,
      status: row.status as SigningKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== null && row.rotated_at !== undefined
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }

  #hydrateEncryption(row: EncryptionRow): EncryptionKey {
    return {
      kid: row.kid,
      alg: row.alg,
      keyRef: ensureBytes(row.key_material),
      status: row.status as EncryptionKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== null && row.rotated_at !== undefined
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }
}

type SigningRow = {
  kid: string
  alg: string
  crv: string | null
  public_jwk: string
  private_jwk: string
  status: string
  created_at: number
  rotated_at: number | null
}

type EncryptionRow = {
  kid: string
  alg: string
  // D1 / bun:sqlite return BLOB columns as ArrayBuffer | Uint8Array depending
  // on the runtime. Accept both.
  key_material: Uint8Array | ArrayBuffer | { type: string; data: number[] }
  status: string
  created_at: number
  rotated_at: number | null
}

function ensureBytes(value: EncryptionRow["key_material"]): Uint8Array {
  if (value instanceof Uint8Array) return value
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (
    value &&
    typeof value === "object" &&
    "data" in (value as Record<string, unknown>)
  ) {
    return new Uint8Array((value as { data: number[] }).data)
  }
  throw new Error("D1KeyStore: unsupported BLOB representation")
}
