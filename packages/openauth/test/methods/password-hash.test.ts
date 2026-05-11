/**
 * Unit tests for the argon2id `PasswordHasher`. The default parameters are
 * slow on purpose; tests override with the minimum legal cost so the suite
 * stays fast.
 */
import { describe, expect, test } from "bun:test"

import { argon2idHasher } from "../../src/domain/password-hash"

describe("argon2idHasher", () => {
  const hasher = argon2idHasher({ t: 1, m: 8, p: 1 })

  test("hash + verify round-trip", async () => {
    const stored = await hasher.hash("correct horse battery staple")
    expect(stored.startsWith("$argon2id$")).toBe(true)
    expect(await hasher.verify("correct horse battery staple", stored)).toBe(true)
  })

  test("verify rejects wrong password", async () => {
    const stored = await hasher.hash("right")
    expect(await hasher.verify("wrong", stored)).toBe(false)
  })

  test("verify rejects malformed stored hash", async () => {
    expect(await hasher.verify("right", "not-a-phc-string")).toBe(false)
  })

  test("verify rejects non-argon2id algorithm", async () => {
    // synthetic argon2i stored hash — must be rejected.
    const fake = "$argon2i$v=19$m=8,t=1,p=1$AAAA$AAAA"
    expect(await hasher.verify("right", fake)).toBe(false)
  })

  test("different salt → different stored value for the same password", async () => {
    const a = await hasher.hash("same")
    const b = await hasher.hash("same")
    expect(a).not.toBe(b)
    expect(await hasher.verify("same", a)).toBe(true)
    expect(await hasher.verify("same", b)).toBe(true)
  })
})
