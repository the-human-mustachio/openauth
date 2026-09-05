/**
 * `rawQueryString` — the signature input for the HTTP-Redirect binding.
 *
 * These assertions are deliberately runtime-independent. The bug they
 * guard against was invisible to the suite for two releases precisely
 * because the old implementation delegated to the runtime's URL encoder:
 * on Bun 1.1 that round-trip preserved bytes and everything passed, on
 * Bun 1.4 it did not and every inbound redirect-binding logout became a
 * 403. A test that goes through `new URL()` would have the same blind
 * spot, so these compare against literal expected strings instead.
 */
import { describe, expect, test } from "bun:test"

import { rawQueryString } from "../../../src/methods/saml-sp/sls"

describe("rawQueryString", () => {
  test("returns the query byte-for-byte, whatever the encoding", () => {
    // A realistic redirect-binding query: base64 with %2B / %2F / %3D,
    // and a SigAlg URI whose colons and slashes are percent-encoded.
    const q =
      "SAMLRequest=fZJNb%2BIwEIb%2FSuR7Ymc%3D" +
      "&RelayState=rs-1" +
      "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256" +
      "&Signature=abc%2Bdef%2Fghi%3D%3D"
    expect(rawQueryString(`https://idp.example/m/corp/sls?${q}`)).toBe(q)
  })

  test("preserves encodings a re-serializer is liable to normalize", () => {
    // Each of these is a case where an encoder might legitimately choose
    // a different-but-equivalent representation. For a signature input,
    // "equivalent" is not good enough — only identical will verify.
    const cases = [
      "a=%7Etilde",
      "a=~tilde",
      "a=%28paren%29",
      "a=(paren)",
      "a=plus+sign",
      "a=plus%2Bsign",
      "a=space%20here",
      "a=upper%2Fcase&b=lower%2fcase",
      "a=%C3%A9",
      "a=trailing%3D%3D",
    ]
    for (const q of cases) {
      expect(rawQueryString(`https://idp.example/sls?${q}`)).toBe(q)
    }
  })

  test("empty when there is no query", () => {
    expect(rawQueryString("https://idp.example/m/corp/sls")).toBe("")
  })

  test("empty for a bare trailing ?", () => {
    expect(rawQueryString("https://idp.example/sls?")).toBe("")
  })

  test("stops at a fragment", () => {
    // Never transmitted to a server, but a hand-built URL might carry one.
    expect(rawQueryString("https://idp.example/sls?a=1&b=2#frag")).toBe(
      "a=1&b=2",
    )
  })

  test("keeps a ? that appears inside a value", () => {
    // Only the FIRST ? separates the query; later ones are data.
    expect(rawQueryString("https://idp.example/sls?a=1&b=x?y")).toBe(
      "a=1&b=x?y",
    )
  })

  test("does not decode — the caller needs octets, not values", () => {
    const q = "SAMLRequest=%3Csaml%3ELogoutRequest%3C%2Fsaml%3E"
    const raw = rawQueryString(`https://idp.example/sls?${q}`)
    expect(raw).toBe(q)
    expect(raw).not.toContain("<saml>")
  })
})
