import { describe, expect, test } from "bun:test"

import { serializeSetCookie } from "../../src/http/cookies"

describe("serializeSetCookie — name validation", () => {
  test("accepts plain reserved-namespace names", () => {
    const out = serializeSetCookie({ name: "auth.flow", value: "abc" })
    expect(out).toContain("auth.flow=")
  })

  test("rejects empty name", () => {
    expect(() =>
      serializeSetCookie({ name: "", value: "x" }),
    ).toThrow(/invalid cookie name/)
  })

  test("rejects names containing '='", () => {
    expect(() =>
      serializeSetCookie({ name: "foo=bar", value: "x" }),
    ).toThrow(/invalid cookie name/)
  })

  test("rejects names containing ';'", () => {
    expect(() =>
      serializeSetCookie({ name: "foo;bar", value: "x" }),
    ).toThrow(/invalid cookie name/)
  })

  test("rejects names containing ','", () => {
    expect(() =>
      serializeSetCookie({ name: "foo,bar", value: "x" }),
    ).toThrow(/invalid cookie name/)
  })

  test("rejects names containing whitespace", () => {
    expect(() =>
      serializeSetCookie({ name: "foo bar", value: "x" }),
    ).toThrow(/invalid cookie name/)
    expect(() =>
      serializeSetCookie({ name: "foo\tbar", value: "x" }),
    ).toThrow(/invalid cookie name/)
  })
})
