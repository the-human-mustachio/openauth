/**
 * DynamoDB `KeyStore`. Single-table — signing keys under `pk="signing-key"`,
 * encryption keys under `pk="encryption-key"`. Private JWKs are stored as
 * JSON strings; encryption key material as base64url. Auto-generates an
 * active key pair on first read.
 *
 * **At-rest protection.** Pass `wrapper: { wrap, unwrap }` to encrypt the
 * private JWK and the encryption-key bytes under a host-controlled master
 * key (typically a KMS Encrypt/Decrypt round trip). Without a wrapper the
 * adapter stores private material in plaintext at rest — acceptable for
 * dev / local use, **not** acceptable for production. See `INTEGRATION.md`
 * §4. The `private_jwk_wrapped` / `key_material_wrapped` attributes record
 * which representation each item uses.
 */
import type { JWK } from "jose"
import { exportJWK, generateKeyPair, importJWK } from "jose"

import {
  base64url,
  generateSymmetricKey,
  randomId,
  utf8,
} from "../../domain/crypto"
import type {
  EncryptionKey,
  KeyStore,
  KeyWrapper,
  SigningKey,
} from "../../ports/key-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type { DynamoExecutor } from "./client"

export type DynamoKeyStoreOptions = {
  exec: DynamoExecutor
  clock?: () => number
  signingAlg?: "ES256" | "EdDSA"
  /**
   * Optional envelope that encrypts private JWKs and encryption-key bytes
   * before they leave the process. STRONGLY RECOMMENDED in production.
   * Pair with a cloud KMS or HSM-backed implementation.
   */
  wrapper?: KeyWrapper
}

export class DynamoKeyStore implements KeyStore {
  #exec: DynamoExecutor
  #clock: () => number
  #signingAlg: "ES256" | "EdDSA"
  #wrapper: KeyWrapper | undefined
  #privateKeyCache = new Map<string, unknown>()

  constructor(opts: DynamoKeyStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
    this.#signingAlg = opts.signingAlg ?? "ES256"
    this.#wrapper = opts.wrapper
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
        authError.internalError(
          "no active signing key (should be unreachable)",
        ),
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
    return ok(await this.#hydrateEncryption(row))
  }

  async getEncryptionKey(kid: string): Promise<Result<EncryptionKey>> {
    const row = await this.#exec.get({
      key: { pk: "encryption-key", sk: kid },
      consistentRead: true,
    })
    if (!row) {
      return err(authError.internalError(`encryption key "${kid}" not found`))
    }
    return ok(await this.#hydrateEncryption(row))
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
    const privateJwkStored = await this.#encodePrivateJwk(privateJwk)
    try {
      await this.#exec.put({
        item: {
          pk: "signing-key",
          sk: kid,
          alg: this.#signingAlg,
          crv: publicJwk.crv ?? null,
          public_jwk: JSON.stringify(publicJwk),
          private_jwk: privateJwkStored,
          private_jwk_wrapped: this.#wrapper !== undefined,
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
    const raw = generateSymmetricKey()
    // DynamoDB stores bytes as Buffer/Uint8Array; base64url-encoded string is
    // portable, supports `aws-sdk-client-mock`, and is marshalled back the
    // same way. Wrapped bytes are encoded the same way after KMS encrypt.
    const stored = this.#wrapper
      ? base64url.encode(await this.#wrapper.wrap(raw))
      : base64url.encode(raw)
    try {
      await this.#exec.put({
        item: {
          pk: "encryption-key",
          sk: kid,
          alg: "A256GCM",
          key_material: stored,
          key_material_wrapped: this.#wrapper !== undefined,
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
      const privateJwk = await this.#decodePrivateJwk(
        String(row.private_jwk),
        row.private_jwk_wrapped === true,
      )
      imported = await importJWK(privateJwk, String(row.alg))
      this.#privateKeyCache.set(kid, imported)
    }
    const publicJwk = JSON.parse(String(row.public_jwk)) as Record<
      string,
      unknown
    >
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

  async #hydrateEncryption(
    row: Record<string, unknown>,
  ): Promise<EncryptionKey> {
    const stored = base64url.decode(String(row.key_material))
    let keyRef = stored
    if (row.key_material_wrapped === true) {
      if (!this.#wrapper) {
        throw new Error(
          "DynamoKeyStore: encryption key item is wrapped but no `wrapper` was supplied — refusing to read",
        )
      }
      keyRef = await this.#wrapper.unwrap(stored)
    }
    return {
      kid: String(row.sk),
      alg: String(row.alg),
      keyRef,
      status: String(row.status) as EncryptionKey["status"],
      createdAt: Number(row.created_at),
      ...(row.rotated_at !== undefined && row.rotated_at !== null
        ? { rotatedAt: Number(row.rotated_at) }
        : {}),
    }
  }

  /**
   * Encode a private JWK for the `private_jwk` attribute. With a wrapper,
   * the JWK bytes are encrypted and stored as `{"ct": <base64url>}` —
   * never as a recognizable JWK at rest. Without one, the JWK is JSON-
   * stringified verbatim (legacy path).
   */
  async #encodePrivateJwk(jwk: JWK): Promise<string> {
    if (!this.#wrapper) return JSON.stringify(jwk)
    const ciphertext = await this.#wrapper.wrap(
      utf8.encode(JSON.stringify(jwk)),
    )
    return JSON.stringify({ ct: base64url.encode(ciphertext) })
  }

  async #decodePrivateJwk(raw: string, wrapped: boolean): Promise<JWK> {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    if (!wrapped) return parsed as unknown as JWK
    if (!this.#wrapper) {
      throw new Error(
        "DynamoKeyStore: signing key item is wrapped but no `wrapper` was supplied — refusing to read",
      )
    }
    const ct = typeof parsed.ct === "string" ? parsed.ct : ""
    if (!ct) {
      throw new Error("DynamoKeyStore: wrapped signing key item missing `ct`")
    }
    const plaintext = await this.#wrapper.unwrap(base64url.decode(ct))
    return JSON.parse(utf8.decode(plaintext)) as JWK
  }
}
