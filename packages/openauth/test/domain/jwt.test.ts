import { describe, expect, test } from "bun:test"

import {
  buildJwksDocument,
  signAccessToken,
  verifyAccessToken,
} from "../../src/domain/jwt"
import { MemoryKeyStore } from "../../src/adapters/memory"
import type { AccessTokenClaims } from "../../src/types/token"
import { asTenantId } from "../../src/types/tenant"

function sampleClaims(): AccessTokenClaims {
  return {
    iss: "https://idp.example",
    sub: "subj-1",
    aud: "rp-1",
    exp: Math.floor(Date.now() / 1000) + 60,
    iat: Math.floor(Date.now() / 1000),
    tid: asTenantId("acme"),
    mid: "stub",
    mkind: "stub",
    scope: "openid email",
    claim: { type: "user", properties: { userId: "u1" } },
  } satisfies AccessTokenClaims
}

describe("jwt: sign + verify", () => {
  test("roundtrip preserves claims", async () => {
    const ks = new MemoryKeyStore()
    const keyRes = await ks.currentSigningKey()
    if (!keyRes.ok) throw new Error("no signing key")
    const signing = keyRes.value
    const claims = sampleClaims()
    const token = await signAccessToken(
      claims,
      signing.privateKeyRef as Parameters<typeof signAccessToken>[1],
      signing.alg,
      signing.kid,
    )
    const verified = await verifyAccessToken(token, [signing])
    expect(verified.sub).toBe(claims.sub)
    expect(verified.tid).toBe(claims.tid)
    expect(verified.scope ?? "").toBe(claims.scope ?? "")
  })

  test("verify rejects unknown kid", async () => {
    const ks1 = new MemoryKeyStore()
    const ks2 = new MemoryKeyStore()
    const r1 = await ks1.currentSigningKey()
    const r2 = await ks2.currentSigningKey()
    if (!r1.ok || !r2.ok) throw new Error("no signing key")
    const k1 = r1.value
    const k2 = r2.value
    const token = await signAccessToken(
      sampleClaims(),
      k1.privateKeyRef as Parameters<typeof signAccessToken>[1],
      k1.alg,
      k1.kid,
    )
    await expect(verifyAccessToken(token, [k2])).rejects.toThrow()
  })

  test("verify rejects alg: none token (hand-crafted)", async () => {
    const ks = new MemoryKeyStore()
    const keyRes = await ks.currentSigningKey()
    if (!keyRes.ok) throw new Error("no signing key")
    const signing = keyRes.value
    const b64 = (s: string): string =>
      Buffer.from(s)
        .toString("base64")
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/, "")
    const header = b64(
      JSON.stringify({ alg: "none", typ: "JWT", kid: signing.kid }),
    )
    const payload = b64(JSON.stringify(sampleClaims()))
    const noneToken = `${header}.${payload}.`
    await expect(verifyAccessToken(noneToken, [signing])).rejects.toThrow()
  })

  test("verify rejects token whose header alg is not in the keys' alg list", async () => {
    const ks = new MemoryKeyStore()
    const keyRes = await ks.currentSigningKey()
    if (!keyRes.ok) throw new Error("no signing key")
    const signing = keyRes.value
    // Forge a header with alg=HS256 + valid kid; jose must refuse because
    // HS256 is not in the derived `algorithms` allow-list.
    const b64 = (s: string): string =>
      Buffer.from(s)
        .toString("base64")
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/, "")
    const header = b64(
      JSON.stringify({ alg: "HS256", typ: "JWT", kid: signing.kid }),
    )
    const payload = b64(JSON.stringify(sampleClaims()))
    const forged = `${header}.${payload}.AAAA`
    await expect(verifyAccessToken(forged, [signing])).rejects.toThrow()
  })

  test("buildJwksDocument exposes kid, alg, use", async () => {
    const ks = new MemoryKeyStore()
    const keysRes = await ks.signingKeys()
    if (!keysRes.ok) throw new Error("no keys")
    const doc = buildJwksDocument(keysRes.value)
    expect(doc.keys.length).toBe(1)
    const jwk = doc.keys[0]!
    expect(jwk.kid).toBe(keysRes.value[0]!.kid)
    expect(jwk.alg).toBe(keysRes.value[0]!.alg)
    expect(jwk.use).toBe("sig")
  })
})
