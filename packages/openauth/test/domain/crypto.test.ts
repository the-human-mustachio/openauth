import { describe, expect, test } from "bun:test"

import {
  base64url,
  decryptPayload,
  encryptPayload,
  generateSymmetricKey,
  hmacSign,
  hmacVerify,
  importHmacKey,
  randomId,
  randomToken,
  sha256,
  timingSafeEqual,
  timingSafeEqualStr,
  utf8,
} from "../../src/domain/crypto"

describe("crypto: random helpers", () => {
  test("randomToken returns distinct base64url strings of stable length", () => {
    const a = randomToken()
    const b = randomToken()
    expect(a).not.toBe(b)
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(a.length).toBeGreaterThanOrEqual(40)
  })

  test("randomId is distinct + shorter than randomToken", () => {
    const a = randomId()
    const b = randomId()
    expect(a).not.toBe(b)
    expect(a.length).toBeLessThan(randomToken().length)
  })
})

describe("crypto: timing-safe compare", () => {
  test("equal bytes return true", () => {
    expect(timingSafeEqual(utf8.encode("hello"), utf8.encode("hello"))).toBe(
      true,
    )
  })
  test("different bytes return false", () => {
    expect(timingSafeEqual(utf8.encode("hello"), utf8.encode("world"))).toBe(
      false,
    )
  })
  test("length mismatch returns false", () => {
    expect(timingSafeEqual(utf8.encode("h"), utf8.encode("hi"))).toBe(false)
  })
  test("string variant agrees with byte variant", () => {
    expect(timingSafeEqualStr("abc", "abc")).toBe(true)
    expect(timingSafeEqualStr("abc", "abd")).toBe(false)
  })
})

describe("crypto: HMAC", () => {
  test("sign + verify roundtrip", async () => {
    const raw = generateSymmetricKey()
    const key = await importHmacKey(raw)
    const msg = utf8.encode("hello, world")
    const sig = await hmacSign(key, msg)
    expect(await hmacVerify(key, sig, msg)).toBe(true)
  })

  test("verify fails on tampered message", async () => {
    const raw = generateSymmetricKey()
    const key = await importHmacKey(raw)
    const msg = utf8.encode("hello, world")
    const sig = await hmacSign(key, msg)
    expect(await hmacVerify(key, sig, utf8.encode("hello, world!"))).toBe(false)
  })

  test("verify fails with different key", async () => {
    const k1 = await importHmacKey(generateSymmetricKey())
    const k2 = await importHmacKey(generateSymmetricKey())
    const sig = await hmacSign(k1, utf8.encode("x"))
    expect(await hmacVerify(k2, sig, utf8.encode("x"))).toBe(false)
  })
})

describe("crypto: encrypt/decrypt payload", () => {
  test("roundtrip preserves JSON-serializable value", async () => {
    const k = generateSymmetricKey()
    const payload = { hello: "world", n: 42, arr: [1, 2, 3] }
    const jwe = await encryptPayload(payload, "kid-1", k)
    const out = await decryptPayload<typeof payload>(jwe, async () => k)
    expect(out).toEqual(payload)
  })

  test("ciphertext does not contain plaintext", async () => {
    const k = generateSymmetricKey()
    const jwe = await encryptPayload({ secret: "shhh-canary-1234" }, "kid", k)
    expect(jwe).not.toContain("shhh-canary-1234")
  })

  test("wrong key during decrypt rejects", async () => {
    const k1 = generateSymmetricKey()
    const k2 = generateSymmetricKey()
    const jwe = await encryptPayload({ x: 1 }, "k1", k1)
    await expect(decryptPayload(jwe, async () => k2)).rejects.toThrow()
  })

  test("rejects non-32-byte keys", async () => {
    await expect(encryptPayload({}, "k", new Uint8Array(16))).rejects.toThrow(
      /32 bytes/,
    )
  })
})

describe("crypto: encodings", () => {
  test("base64url roundtrip", () => {
    const raw = new Uint8Array([1, 2, 3, 4, 5])
    expect(base64url.decode(base64url.encode(raw))).toEqual(raw)
  })

  test("sha256 produces 32 bytes", async () => {
    const d = await sha256("hello")
    expect(d.length).toBe(32)
  })
})
