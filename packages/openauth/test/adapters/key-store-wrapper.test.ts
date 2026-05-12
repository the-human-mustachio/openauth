/**
 * `KeyWrapper` round-trip + at-rest opacity for the Postgres and Dynamo
 * `KeyStore` adapters.
 *
 * The signing-key private JWK and the encryption-key bytes are required to
 * be unrecognizable in the underlying row / item when a wrapper is wired —
 * a read-only DB compromise must not yield token-forging power.
 */
import { PGlite } from "@electric-sql/pglite"
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test"

import { DynamoKeyStore } from "../../src/adapters/dynamo"
import {
  fromPGlite,
  migrate,
  PostgresKeyStore,
  type PostgresExecutor,
} from "../../src/adapters/postgres"
import type { KeyWrapper } from "../../src/ports/key-store"

import { createDynamoShim } from "../helpers/dynamo-shim"

const { subtle } = crypto

/** AES-256-GCM wrapper backed by an in-process random key. */
async function createWrapper(): Promise<KeyWrapper> {
  const raw = new Uint8Array(32)
  crypto.getRandomValues(raw)
  const key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ])
  return {
    async wrap(plaintext) {
      const iv = new Uint8Array(12)
      crypto.getRandomValues(iv)
      const ct = new Uint8Array(
        await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
      )
      const out = new Uint8Array(iv.length + ct.length)
      out.set(iv, 0)
      out.set(ct, iv.length)
      return out
    },
    async unwrap(ciphertext) {
      const iv = ciphertext.slice(0, 12)
      const ct = ciphertext.slice(12)
      return new Uint8Array(
        await subtle.decrypt({ name: "AES-GCM", iv }, key, ct),
      )
    },
  }
}

describe("PostgresKeyStore — wrapper (envelope at rest)", () => {
  let pglite: PGlite
  let exec: PostgresExecutor

  beforeAll(async () => {
    pglite = new PGlite()
    exec = fromPGlite(pglite)
    await migrate(exec)
  })

  afterAll(async () => {
    await pglite.close()
  })

  beforeEach(async () => {
    await exec.query(`TRUNCATE TABLE openauth_signing_keys CASCADE`)
    await exec.query(`TRUNCATE TABLE openauth_encryption_keys CASCADE`)
  })

  test("signing-key private JWK is wrapped (no plaintext JWK shape on disk)", async () => {
    const wrapper = await createWrapper()
    const store = new PostgresKeyStore({ exec, wrapper })

    const current = await store.currentSigningKey()
    expect(current.ok).toBe(true)
    if (!current.ok) return

    const rows = await exec.query<{
      private_jwk: unknown
      private_jwk_wrapped: boolean
    }>(`SELECT private_jwk, private_jwk_wrapped FROM openauth_signing_keys`)
    expect(rows.rows.length).toBe(1)
    const row = rows.rows[0]!
    expect(row.private_jwk_wrapped).toBe(true)
    const raw =
      typeof row.private_jwk === "string"
        ? row.private_jwk
        : JSON.stringify(row.private_jwk)
    // A plaintext JWK has `kty` and `d`. The wrapped envelope must not.
    expect(raw).not.toContain('"d":')
    expect(raw).not.toContain('"kty":')
    expect(raw).toContain('"ct":')
  })

  test("encryption-key bytes are wrapped at rest + decrypt round-trips", async () => {
    const wrapper = await createWrapper()
    const store = new PostgresKeyStore({ exec, wrapper })

    const current = await store.currentEncryptionKey()
    expect(current.ok).toBe(true)
    if (!current.ok) return
    // Re-fetch by kid — the unwrap path must produce the same plaintext.
    const looked = await store.getEncryptionKey(current.value.kid)
    expect(looked.ok).toBe(true)
    if (!looked.ok) return
    const a = current.value.keyRef as Uint8Array
    const b = looked.value.keyRef as Uint8Array
    expect(a.byteLength).toBe(32)
    expect(Array.from(b)).toEqual(Array.from(a))

    const rows = await exec.query<{
      key_material_wrapped: boolean
      key_material: Uint8Array | { type: string; data: number[] } | string
    }>(
      `SELECT key_material, key_material_wrapped FROM openauth_encryption_keys`,
    )
    expect(rows.rows[0]!.key_material_wrapped).toBe(true)
  })

  test("reading a wrapped row without a wrapper throws", async () => {
    const wrapper = await createWrapper()
    const writer = new PostgresKeyStore({ exec, wrapper })
    await writer.currentSigningKey()
    await writer.currentEncryptionKey()

    const reader = new PostgresKeyStore({ exec })
    let threw = false
    try {
      await reader.currentSigningKey()
    } catch (e) {
      threw = true
      expect(String(e)).toContain("wrapped")
    }
    expect(threw).toBe(true)
  })

  test("unwrapped (legacy) rows still read when a wrapper is later wired", async () => {
    const legacy = new PostgresKeyStore({ exec })
    const before = await legacy.currentSigningKey()
    expect(before.ok).toBe(true)
    if (!before.ok) return
    const beforeKid = before.value.kid

    const wrapper = await createWrapper()
    const upgraded = new PostgresKeyStore({ exec, wrapper })
    const after = await upgraded.currentSigningKey()
    expect(after.ok).toBe(true)
    if (after.ok) expect(after.value.kid).toBe(beforeKid)
  })
})

describe("DynamoKeyStore — wrapper (envelope at rest)", () => {
  test("signing-key private JWK is wrapped (no plaintext JWK shape on disk)", async () => {
    const wrapper = await createWrapper()
    const exec = createDynamoShim()
    const store = new DynamoKeyStore({ exec, wrapper })

    const current = await store.currentSigningKey()
    expect(current.ok).toBe(true)

    const items = await exec.query({ pk: "signing-key", consistentRead: true })
    expect(items.length).toBe(1)
    const item = items[0]!
    expect(item.private_jwk_wrapped).toBe(true)
    const raw = String(item.private_jwk)
    expect(raw).not.toContain('"d":')
    expect(raw).not.toContain('"kty":')
    expect(raw).toContain('"ct":')
  })

  test("encryption-key bytes are wrapped + round-trip via getEncryptionKey", async () => {
    const wrapper = await createWrapper()
    const exec = createDynamoShim()
    const store = new DynamoKeyStore({ exec, wrapper })

    const current = await store.currentEncryptionKey()
    expect(current.ok).toBe(true)
    if (!current.ok) return
    const looked = await store.getEncryptionKey(current.value.kid)
    expect(looked.ok).toBe(true)
    if (!looked.ok) return
    expect(Array.from(looked.value.keyRef as Uint8Array)).toEqual(
      Array.from(current.value.keyRef as Uint8Array),
    )

    const items = await exec.query({
      pk: "encryption-key",
      consistentRead: true,
    })
    expect(items[0]!.key_material_wrapped).toBe(true)
  })

  test("reading a wrapped row without a wrapper throws", async () => {
    const wrapper = await createWrapper()
    const exec = createDynamoShim()
    const writer = new DynamoKeyStore({ exec, wrapper })
    await writer.currentSigningKey()
    const reader = new DynamoKeyStore({ exec })
    let threw = false
    try {
      await reader.currentSigningKey()
    } catch (e) {
      threw = true
      expect(String(e)).toContain("wrapped")
    }
    expect(threw).toBe(true)
  })
})
