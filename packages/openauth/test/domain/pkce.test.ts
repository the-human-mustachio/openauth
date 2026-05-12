import { describe, expect, test } from "bun:test"

import { s256Challenge, validatePkce } from "../../src/domain/pkce"
import { randomToken } from "../../src/domain/crypto"

describe("pkce: validatePkce", () => {
  test("S256 happy path", async () => {
    const verifier = randomToken() + randomToken() // ~88 chars
    const challenge = await s256Challenge(verifier)
    expect(await validatePkce(verifier, challenge)).toBe(true)
  })

  test("rejects mismatched verifier", async () => {
    const verifier1 = randomToken() + randomToken()
    const verifier2 = randomToken() + randomToken()
    const challenge = await s256Challenge(verifier1)
    expect(await validatePkce(verifier2, challenge)).toBe(false)
  })

  test("rejects verifier shorter than 43 chars", async () => {
    const challenge = await s256Challenge("short")
    expect(await validatePkce("short", challenge)).toBe(false)
  })

  test("rejects verifier longer than 128 chars", async () => {
    const long = "x".repeat(130)
    const challenge = await s256Challenge(long)
    expect(await validatePkce(long, challenge)).toBe(false)
  })

  test("rejects non-string inputs", async () => {
    expect(await validatePkce(undefined as unknown as string, "x")).toBe(false)
    expect(await validatePkce("x", undefined as unknown as string)).toBe(false)
  })

  test("known-good RFC 7636 example", async () => {
    // RFC 7636 §4.6 reference vector
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    expect(await s256Challenge(verifier)).toBe(expected)
  })
})
