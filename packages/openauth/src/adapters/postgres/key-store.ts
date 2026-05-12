/**
 * Postgres `KeyStore`.
 *
 * Signing keys are persisted as a pair of JWK blobs (public + private) so
 * the framework can transparently `importJWK(privateKeyRef)` on first use.
 * Encryption keys are stored as raw bytes in a `bytea` column.
 *
 * On first read, if no active signing or encryption key exists the adapter
 * auto-generates one. This keeps the developer experience aligned with the
 * memory adapter (no manual bootstrap step) while still respecting whatever
 * keys an operator may have provisioned out-of-band.
 *
 * **At-rest protection.** Pass `wrapper: { wrap, unwrap }` to encrypt the
 * private JWK and the encryption-key bytes under a host-controlled master
 * key (typically a KMS Encrypt/Decrypt round trip). Without a wrapper the
 * adapter stores private material in plaintext at rest — acceptable for
 * dev / local use, **not** acceptable for production. See `INTEGRATION.md`
 * §4. The `private_jwk_wrapped` / `key_material_wrapped` boolean columns
 * record which representation each row uses, so flipping a wrapper on for
 * an existing deployment is a (forthcoming) re-wrap migration rather than
 * a schema change.
 *
 * Rotation (`rotateSigningKeys` / `rotateEncryptionKeys`) is left as a Phase
 * 8 deliverable — schema columns exist for `status` and `rotated_at`, so the
 * later implementation will be a series of `UPDATE` statements without
 * needing a migration.
 */
import type { JWK } from "jose"
import { exportJWK, generateKeyPair, importJWK } from "jose"

import { base64url, generateSymmetricKey, randomId, utf8 } from "../../domain/crypto"
import type {
  EncryptionKey,
  KeyStore,
  KeyWrapper,
  SigningKey,
} from "../../ports/key-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type { PostgresExecutor } from "./executor"

export type PostgresKeyStoreOptions = {
  exec: PostgresExecutor
  clock?: () => number
  signingAlg?: "ES256" | "EdDSA"
  /**
   * Optional envelope that encrypts private JWKs and encryption-key bytes
   * before they leave the process. STRONGLY RECOMMENDED in production.
   * Pair with a cloud KMS or HSM-backed implementation.
   */
  wrapper?: KeyWrapper
}

export class PostgresKeyStore implements KeyStore {
  #exec: PostgresExecutor
  #clock: () => number
  #signingAlg: "ES256" | "EdDSA"
  #wrapper: KeyWrapper | undefined
  // Cache imported private keys so we don't re-import on every sign.
  #privateKeyCache = new Map<string, unknown>()

  constructor(opts: PostgresKeyStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
    this.#signingAlg = opts.signingAlg ?? "ES256"
    this.#wrapper = opts.wrapper
  }

  async currentSigningKey(): Promise<Result<SigningKey>> {
    await this.#ensureSigningKey()
    const rows = await this.#selectSigningRows(`status = 'active'`)
    if (rows.length === 0) {
      return err(
        authError.internalError("no active signing key (should be unreachable)"),
      )
    }
    const key = await this.#hydrateSigningKey(rows[0]!)
    return ok(key)
  }

  async signingKeys(): Promise<Result<SigningKey[]>> {
    await this.#ensureSigningKey()
    const rows = await this.#selectSigningRows(`status IN ('active','next','retired')`)
    const keys = await Promise.all(rows.map((r) => this.#hydrateSigningKey(r)))
    return ok(keys)
  }

  async currentEncryptionKey(): Promise<Result<EncryptionKey>> {
    await this.#ensureEncryptionKey()
    const rows = await this.#selectEncryptionRows(`status = 'active'`)
    if (rows.length === 0) {
      return err(
        authError.internalError(
          "no active encryption key (should be unreachable)",
        ),
      )
    }
    return ok(await this.#hydrateEncryptionKey(rows[0]!))
  }

  async getEncryptionKey(kid: string): Promise<Result<EncryptionKey>> {
    let row: EncryptionKeyRow | undefined
    try {
      const result = await this.#exec.query<EncryptionKeyRow>(
        `SELECT kid, alg, key_material, key_material_wrapped, status, created_at, rotated_at
           FROM openauth_encryption_keys WHERE kid = $1`,
        [kid],
      )
      row = result.rows[0]
    } catch (e) {
      return err(authError.internalError("getEncryptionKey: query failed", e))
    }
    if (!row) {
      return err(authError.internalError(`encryption key "${kid}" not found`))
    }
    return ok(await this.#hydrateEncryptionKey(row))
  }

  // --- bootstrap -------------------------------------------------------

  async #ensureSigningKey(): Promise<void> {
    const rows = await this.#selectSigningRows(`status = 'active'`)
    if (rows.length > 0) return
    const { publicKey, privateKey } = await generateKeyPair(this.#signingAlg, {
      extractable: true,
    })
    const publicJwk = await exportJWK(publicKey)
    const privateJwk = await exportJWK(privateKey)
    const kid = randomId()
    const { jsonPayload, wrapped } = await this.#encodePrivateJwk(privateJwk)
    await this.#exec.query(
      `INSERT INTO openauth_signing_keys
         (kid, alg, crv, public_jwk, private_jwk, private_jwk_wrapped, status, created_at)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, 'active', $7)
       ON CONFLICT (kid) DO NOTHING`,
      [
        kid,
        this.#signingAlg,
        publicJwk.crv ?? null,
        JSON.stringify(publicJwk),
        jsonPayload,
        wrapped,
        this.#clock(),
      ],
    )
  }

  async #ensureEncryptionKey(): Promise<void> {
    const rows = await this.#selectEncryptionRows(`status = 'active'`)
    if (rows.length > 0) return
    const kid = randomId()
    const raw = generateSymmetricKey() // 32 bytes
    const stored = this.#wrapper ? await this.#wrapper.wrap(raw) : raw
    await this.#exec.query(
      `INSERT INTO openauth_encryption_keys
         (kid, alg, key_material, key_material_wrapped, status, created_at)
       VALUES ($1, $2, $3, $4, 'active', $5)
       ON CONFLICT (kid) DO NOTHING`,
      [kid, "A256GCM", stored, this.#wrapper !== undefined, this.#clock()],
    )
  }

  /**
   * Encode a private JWK for `private_jwk jsonb` storage. With a wrapper,
   * the plaintext JWK bytes are encrypted and stored as `{"ct": <base64url>}`
   * — never as a recognizable JWK on disk. Without one, the JWK is stored
   * verbatim.
   */
  async #encodePrivateJwk(
    jwk: JWK,
  ): Promise<{ jsonPayload: string; wrapped: boolean }> {
    if (!this.#wrapper) {
      return { jsonPayload: JSON.stringify(jwk), wrapped: false }
    }
    const ciphertext = await this.#wrapper.wrap(
      utf8.encode(JSON.stringify(jwk)),
    )
    return {
      jsonPayload: JSON.stringify({ ct: base64url.encode(ciphertext) }),
      wrapped: true,
    }
  }

  async #decodePrivateJwk(
    raw: unknown,
    wrapped: boolean,
  ): Promise<JWK> {
    const parsed =
      typeof raw === "string"
        ? (JSON.parse(raw) as Record<string, unknown>)
        : (raw as Record<string, unknown>)
    if (!wrapped) return parsed as unknown as JWK
    if (!this.#wrapper) {
      throw new Error(
        "PostgresKeyStore: signing key row is wrapped but no `wrapper` was supplied — refusing to read",
      )
    }
    const ct = typeof parsed.ct === "string" ? parsed.ct : ""
    if (!ct) {
      throw new Error("PostgresKeyStore: wrapped signing key row missing `ct`")
    }
    const plaintext = await this.#wrapper.unwrap(base64url.decode(ct))
    return JSON.parse(utf8.decode(plaintext)) as JWK
  }

  // --- helpers --------------------------------------------------------

  async #selectSigningRows(where: string): Promise<SigningKeyRow[]> {
    const result = await this.#exec.query<SigningKeyRow>(
      `SELECT kid, alg, crv, public_jwk, private_jwk, private_jwk_wrapped,
              status, created_at, rotated_at
         FROM openauth_signing_keys WHERE ${where}`,
    )
    return result.rows
  }

  async #selectEncryptionRows(where: string): Promise<EncryptionKeyRow[]> {
    const result = await this.#exec.query<EncryptionKeyRow>(
      `SELECT kid, alg, key_material, key_material_wrapped, status, created_at, rotated_at
         FROM openauth_encryption_keys WHERE ${where}`,
    )
    return result.rows
  }

  async #hydrateSigningKey(row: SigningKeyRow): Promise<SigningKey> {
    let imported = this.#privateKeyCache.get(row.kid)
    if (!imported) {
      const privateJwk = await this.#decodePrivateJwk(
        row.private_jwk,
        row.private_jwk_wrapped === true,
      )
      imported = await importJWK(privateJwk, row.alg)
      this.#privateKeyCache.set(row.kid, imported)
    }
    const publicJwk =
      typeof row.public_jwk === "string"
        ? (JSON.parse(row.public_jwk) as Record<string, unknown>)
        : (row.public_jwk as Record<string, unknown>)
    return {
      kid: row.kid,
      alg: row.alg,
      ...(row.crv ? { crv: row.crv } : {}),
      publicJwk,
      privateKeyRef: imported,
      status: row.status as SigningKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== null && row.rotated_at !== undefined
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }

  async #hydrateEncryptionKey(row: EncryptionKeyRow): Promise<EncryptionKey> {
    const stored = ensureBytes(row.key_material)
    let keyRef = stored
    if (row.key_material_wrapped === true) {
      if (!this.#wrapper) {
        throw new Error(
          "PostgresKeyStore: encryption key row is wrapped but no `wrapper` was supplied — refusing to read",
        )
      }
      keyRef = await this.#wrapper.unwrap(stored)
    }
    return {
      kid: row.kid,
      alg: row.alg,
      keyRef,
      status: row.status as EncryptionKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== null && row.rotated_at !== undefined
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }
}

type SigningKeyRow = {
  kid: string
  alg: string
  crv: string | null
  public_jwk: unknown
  private_jwk: unknown
  private_jwk_wrapped: boolean | number | null
  status: string
  created_at: string | number
  rotated_at: string | number | null
}

type EncryptionKeyRow = {
  kid: string
  alg: string
  key_material: Uint8Array | { type: string; data: number[] } | string
  key_material_wrapped: boolean | number | null
  status: string
  created_at: string | number
  rotated_at: string | number | null
}

/**
 * Some drivers return `bytea` columns as `Uint8Array`; some return
 * `Buffer`; some return base64-decoded strings or `{ type: "Buffer", data: [...] }`.
 * Normalize to a plain `Uint8Array` so the encryption path is driver-agnostic.
 */
function ensureBytes(value: EncryptionKeyRow["key_material"]): Uint8Array {
  if (value instanceof Uint8Array) return value
  if (typeof value === "string") {
    // Best-effort: hex-encoded by postgres-js default; PGlite returns Uint8Array.
    if (/^\\x[0-9a-fA-F]+$/.test(value)) {
      const hex = value.slice(2)
      const out = new Uint8Array(hex.length / 2)
      for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
      }
      return out
    }
    return new TextEncoder().encode(value)
  }
  if (
    value &&
    typeof value === "object" &&
    "data" in (value as Record<string, unknown>)
  ) {
    return new Uint8Array((value as { data: number[] }).data)
  }
  throw new Error("PostgresKeyStore: unsupported bytea representation")
}
