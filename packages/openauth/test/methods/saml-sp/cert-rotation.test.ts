/**
 * `selectActiveCertPems` — pure window filter backing the node-saml
 * cert-rotation shim. The cases that matter for hot rotation:
 * unbounded certs always apply, `notBefore` is inclusive, `notAfter`
 * is exclusive, and overlapping windows return both certs so in-flight
 * assertions from either key still verify.
 */
import { describe, expect, test } from "bun:test"

import { selectActiveCertPems } from "../../../src/methods/saml-sp/cert-rotation"

const NOW = 1_700_000_000_000

describe("selectActiveCertPems", () => {
  test("cert with no bounds is always active", () => {
    expect(selectActiveCertPems([{ pem: "A" }], NOW)).toEqual(["A"])
    expect(selectActiveCertPems([{ pem: "A" }], 0)).toEqual(["A"])
  })

  test("notBefore is inclusive", () => {
    expect(
      selectActiveCertPems([{ pem: "A", notBefore: NOW }], NOW),
    ).toEqual(["A"])
    expect(
      selectActiveCertPems([{ pem: "A", notBefore: NOW + 1 }], NOW),
    ).toEqual([])
  })

  test("notAfter is exclusive", () => {
    expect(
      selectActiveCertPems([{ pem: "A", notAfter: NOW + 1 }], NOW),
    ).toEqual(["A"])
    expect(
      selectActiveCertPems([{ pem: "A", notAfter: NOW }], NOW),
    ).toEqual([])
  })

  test("overlapping rotation window returns both certs", () => {
    const certs = [
      { pem: "OLD", notAfter: NOW + 10_000 },
      { pem: "NEW", notBefore: NOW - 10_000 },
    ]
    expect(selectActiveCertPems(certs, NOW)).toEqual(["OLD", "NEW"])
  })

  test("expired-only set returns empty (caller surfaces a config error)", () => {
    const certs = [
      { pem: "OLD", notAfter: NOW - 1 },
      { pem: "FUTURE", notBefore: NOW + 1 },
    ]
    expect(selectActiveCertPems(certs, NOW)).toEqual([])
  })

  test("preserves order and only the active subset", () => {
    const certs = [
      { pem: "A" },
      { pem: "B", notAfter: NOW - 1 },
      { pem: "C", notBefore: NOW - 1, notAfter: NOW + 1 },
    ]
    expect(selectActiveCertPems(certs, NOW)).toEqual(["A", "C"])
  })
})
