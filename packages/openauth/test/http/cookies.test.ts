import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test"

import { applyResponsePolicy, serializeSetCookie } from "../../src/http/cookies"

describe("serializeSetCookie — name validation", () => {
  test("accepts plain reserved-namespace names", () => {
    const out = serializeSetCookie({ name: "auth.flow", value: "abc" })
    expect(out).toContain("auth.flow=")
  })

  test("rejects empty name", () => {
    expect(() => serializeSetCookie({ name: "", value: "x" })).toThrow(
      /invalid cookie name/,
    )
  })

  test("rejects names containing '='", () => {
    expect(() => serializeSetCookie({ name: "foo=bar", value: "x" })).toThrow(
      /invalid cookie name/,
    )
  })

  test("rejects names containing ';'", () => {
    expect(() => serializeSetCookie({ name: "foo;bar", value: "x" })).toThrow(
      /invalid cookie name/,
    )
  })

  test("rejects names containing ','", () => {
    expect(() => serializeSetCookie({ name: "foo,bar", value: "x" })).toThrow(
      /invalid cookie name/,
    )
  })

  test("rejects names containing whitespace", () => {
    expect(() => serializeSetCookie({ name: "foo bar", value: "x" })).toThrow(
      /invalid cookie name/,
    )
    expect(() => serializeSetCookie({ name: "foo\tbar", value: "x" })).toThrow(
      /invalid cookie name/,
    )
  })
})

describe("applyResponsePolicy — strip warnings", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let warnSpy: any
  beforeEach(() => {
    warnSpy = mock(() => {})
    console.warn = warnSpy
  })
  afterEach(() => {
    warnSpy.mockClear()
  })

  test("silent when no stripped headers are present", () => {
    const res = new Response("ok", { headers: { "X-Custom": "v" } })
    applyResponsePolicy(res)
    expect(warnSpy).not.toHaveBeenCalled()
  })

  test("warns and drops method-set Set-Cookie", () => {
    const res = new Response("ok", { headers: { "Set-Cookie": "a=b" } })
    const out = applyResponsePolicy(res)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(warnSpy.mock.calls[0][0]).toContain("set-cookie")
    expect(out.headers.get("set-cookie")).toBeNull()
  })

  test("warns and drops CSP / framing headers", () => {
    const res = new Response("ok", {
      headers: {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
      },
    })
    applyResponsePolicy(res)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    const msg = warnSpy.mock.calls[0][0]
    expect(msg).toContain("content-security-policy")
    expect(msg).toContain("x-frame-options")
  })

  test("warns when method overrides Cache-Control", () => {
    const res = new Response("ok", {
      headers: { "Cache-Control": "max-age=3600" },
    })
    const out = applyResponsePolicy(res)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    // Framework default wins.
    expect(out.headers.get("Cache-Control")).toBe("no-store")
  })
})
