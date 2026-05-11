/**
 * Test helper — build a `StateKeyRing` with a deterministic active key.
 */
import type { StateKeyRing } from "../../src/types/tenant"

export function buildStateKeys(seed = 1): StateKeyRing {
  const key = new Uint8Array(32)
  for (let i = 0; i < 32; i++) key[i] = (seed + i) & 0xff
  const entry = { kid: `test-${seed}`, key }
  return { active: entry, verify: [entry] }
}

export function buildStateKeysWithOverlap(): StateKeyRing {
  const a = (seed: number) => {
    const key = new Uint8Array(32)
    for (let i = 0; i < 32; i++) key[i] = (seed + i) & 0xff
    return { kid: `test-${seed}`, key }
  }
  const active = a(2)
  const prev = a(1)
  return { active, verify: [active, prev] }
}
