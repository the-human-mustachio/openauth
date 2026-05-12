import { describe, expect, test } from "bun:test"

import {
  mintStateEnvelope,
  verifyStateEnvelope,
} from "../../src/domain/state-envelope"
import { asTenantId } from "../../src/types/tenant"
import {
  buildStateKeys,
  buildStateKeysWithOverlap,
} from "../helpers/state-keys"

const tenantId = asTenantId("acme")

describe("state-envelope: mint + verify", () => {
  test("roundtrip with single active key", async () => {
    const ring = buildStateKeys()
    const minted = await mintStateEnvelope(
      { tenantId, flowId: "flow-1", nonce: "n-1" },
      ring,
    )
    const verified = await verifyStateEnvelope(minted, ring)
    expect(verified.ok).toBe(true)
    if (!verified.ok) return
    expect(verified.value.tenantId).toBe(tenantId)
    expect(verified.value.flowId).toBe("flow-1")
    expect(verified.value.nonce).toBe("n-1")
    expect(verified.value.kid).toBe(ring.active.kid)
  })

  test("verify accepts previous key during overlap", async () => {
    const ring = buildStateKeysWithOverlap()
    // Mint under the previous key by swapping active.
    const prev = ring.verify[1]!
    const ringPrev = { active: prev, verify: [prev] }
    const minted = await mintStateEnvelope(
      { tenantId, flowId: "flow-x", nonce: "n-x" },
      ringPrev,
    )
    // Verify under the overlap ring — should accept the previous key.
    const verified = await verifyStateEnvelope(minted, ring)
    expect(verified.ok).toBe(true)
  })

  test("rejects malformed state", async () => {
    const ring = buildStateKeys()
    const r1 = await verifyStateEnvelope("not-a-state", ring)
    expect(r1.ok).toBe(false)
    const r2 = await verifyStateEnvelope("a.b.c", ring) // too many parts
    expect(r2.ok).toBe(false)
    const r3 = await verifyStateEnvelope("", ring)
    expect(r3.ok).toBe(false)
  })

  test("rejects state signed by an unknown key", async () => {
    const ringA = buildStateKeys(1)
    const ringB = buildStateKeys(2)
    const minted = await mintStateEnvelope(
      { tenantId, flowId: "f", nonce: "n" },
      ringA,
    )
    const verified = await verifyStateEnvelope(minted, ringB)
    expect(verified.ok).toBe(false)
  })

  test("rejects tampered payload (signature mismatch)", async () => {
    const ring = buildStateKeys()
    const minted = await mintStateEnvelope(
      { tenantId, flowId: "f", nonce: "n" },
      ring,
    )
    // Flip a byte in the payload portion.
    const [headerB64u, sig] = minted.split(".")
    const tampered = `${headerB64u!.slice(0, -1)}X.${sig}`
    const verified = await verifyStateEnvelope(tampered, ring)
    expect(verified.ok).toBe(false)
  })
})
