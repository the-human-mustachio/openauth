/**
 * RFC 9449 — Demonstration of Proof-of-Possession (DPoP) conformance.
 *
 * Each case cites the relevant section. The endpoint is exercised through
 * `createIdP` so the `DPoP:` header handling at `/token` and `/userinfo`
 * goes through the real Hono router + signature-verification pipeline.
 */
import { describe, expect, test } from "bun:test"
import {
  type JWK,
  type KeyLike,
  SignJWT,
  exportJWK,
  generateKeyPair,
} from "jose"

import { createIdP } from "../../src/index"
import { asTenantId } from "../../src/types/tenant"
import { ok } from "../../src/types/result"
import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { s256Challenge } from "../../src/domain/pkce"
import { computeAth } from "../../src/domain/dpop"
import { verifyAccessToken } from "../../src/domain/jwt"

import { authorizeUrl, driveCallback } from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

import type { TokenResponse } from "../../src/types/token"
import { testSubjects } from "../helpers/subjects"

type DpopKey = {
  publicJwk: JWK
  privateKey: KeyLike
}

async function newDpopKey(): Promise<DpopKey> {
  // ES256 — the universally-accepted DPoP alg.
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  })
  const publicJwk = await exportJWK(publicKey)
  return { publicJwk, privateKey }
}

let jtiSeq = 0
function nextJti(): string {
  jtiSeq += 1
  return `jti-${Date.now()}-${jtiSeq}`
}

type ProofOpts = {
  key: DpopKey
  htu: string
  htm: string
  iat?: number
  jti?: string
  ath?: string
  alg?: string
  typ?: string
}

async function makeProof(opts: ProofOpts): Promise<string> {
  const payload: Record<string, unknown> = {
    htu: opts.htu,
    htm: opts.htm,
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
    jti: opts.jti ?? nextJti(),
  }
  if (opts.ath !== undefined) payload.ath = opts.ath
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: opts.alg ?? "ES256",
      typ: opts.typ ?? "dpop+jwt",
      jwk: opts.key.publicJwk,
    })
    .sign(opts.key.privateKey)
}

async function buildDpopHarness(
  opts: {
    dpopRequired?: boolean
    clientType?: "public" | "confidential"
    clientSecret?: string
  } = {},
) {
  const tenant = await buildTenant({
    methods: [{ id: "stub", kind: "stub" }],
    ...(opts.clientType !== undefined ? { clientType: opts.clientType } : {}),
    ...(opts.clientSecret !== undefined
      ? { clientSecretPlain: opts.clientSecret }
      : {}),
  })
  if (opts.dpopRequired) {
    ;(tenant.clients[0] as { dpopRequired?: boolean }).dpopRequired = true
  }
  const issuerUrl = "https://idp.example"
  const auditLog = new MemoryAuditLog()
  const configStore = new MemoryConfigStore({ seed: [tenant] })
  const keyStore = new MemoryKeyStore({})
  const tokenStore = new MemoryTokenStore({ keyStore })
  const sessionStore = new MemorySessionStore({})
  const idp = createIdP({
    resolveTenant: async () => ok(asTenantId(tenant.id)),
    stateKeys: buildStateKeys(),
    configStore,
    tokenStore,
    sessionStore,
    keyStore,
    auditLog,
    issuerUrl,
    methods: { stub: redirectFactory({ kind: "stub" }) as never },
    subjects: testSubjects,
    success: async ({ providerSubject }) =>
      ({
        type: "user",
        properties: { userId: providerSubject },
      }) as never,
  })
  return { idp, issuerUrl, keyStore, tokenStore }
}

async function authorize(
  h: Awaited<ReturnType<typeof buildDpopHarness>>,
  verifier: string,
): Promise<string> {
  const challenge = await s256Challenge(verifier)
  const authorizeRes = await h.idp.handle(
    new Request(
      authorizeUrl(h.issuerUrl, {
        response_type: "code",
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        scope: "openid",
        state: "rp-csrf",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }),
    ),
  )
  const cb = await driveCallback(h.idp, authorizeRes.headers.get("location")!)
  return new URL(cb.headers.get("location")!).searchParams.get("code")!
}

describe("RFC 9449 — DPoP conformance", () => {
  // ─── case DPOP-1 ── §6 access token carries cnf.jkt; token_type=DPoP ──
  test("DPOP-1. /token with DPoP proof issues token_type=DPoP with cnf.jkt", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const proof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as TokenResponse
    expect(body.token_type).toBe("DPoP")
    expect(body.access_token).toBeString()

    const keysRes = await h.keyStore.signingKeys()
    if (!keysRes.ok) throw new Error("signingKeys err")
    const claims = await verifyAccessToken(body.access_token, keysRes.value, {
      issuer: h.issuerUrl,
    })
    expect(claims.cnf).toBeDefined()
    expect(claims.cnf!.jkt).toBeString()
  })

  // ─── case DPOP-2 ── §7 /userinfo with matching proof + ath → 200 ──
  test("DPOP-2. /userinfo with DPoP-bound token + matching proof → 200", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const tokenProof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const tokenRes = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: tokenProof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    const body = (await tokenRes.json()) as TokenResponse
    const ath = await computeAth(body.access_token)
    const usinfoProof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/userinfo",
      htm: "GET",
      ath,
    })
    const userinfo = await h.idp.handle(
      new Request(h.issuerUrl + "/userinfo", {
        headers: {
          authorization: `DPoP ${body.access_token}`,
          dpop: usinfoProof,
        },
      }),
    )
    expect(userinfo.status).toBe(200)
  })

  // ─── case DPOP-3 ── §7 proof from different key → 401 invalid_dpop_proof ──
  test("DPOP-3. /userinfo with DPoP proof from a different key → 401", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const original = await newDpopKey()
    const tokenProof = await makeProof({
      key: original,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const body = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/token", {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            dpop: tokenProof,
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: "rp-1",
            redirect_uri: "https://app.example/callback",
            code_verifier: verifier,
          }).toString(),
        }),
      )
      .then((r) => r.json())) as TokenResponse
    const attacker = await newDpopKey()
    const stolenProof = await makeProof({
      key: attacker,
      htu: h.issuerUrl + "/userinfo",
      htm: "GET",
      ath: await computeAth(body.access_token),
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/userinfo", {
        headers: {
          authorization: `DPoP ${body.access_token}`,
          dpop: stolenProof,
        },
      }),
    )
    expect(res.status).toBe(401)
    const err = (await res.json()) as { error: string }
    expect(err.error).toBe("invalid_dpop_proof")
  })

  // ─── case DPOP-4 ── §11 jti replay rejected ──
  test("DPOP-4. /token with replayed jti → invalid_dpop_proof", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const sharedJti = nextJti()
    const proof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "POST",
      jti: sharedJti,
    })
    const first = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    expect(first.status).toBe(200)
    // Second presentation of the same proof — same jti — must reject.
    const second = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    expect(second.status).toBe(400)
    expect(((await second.json()) as { error: string }).error).toBe(
      "invalid_dpop_proof",
    )
  })

  // ─── case DPOP-5 ── §4.3 htm mismatch ──
  test("DPOP-5. /token with htm=GET (mismatch) → invalid_dpop_proof", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const proof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "GET", // wrong
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_dpop_proof",
    )
  })

  // ─── case DPOP-6 ── §4.3 htu mismatch ──
  test("DPOP-6. /token with wrong htu → invalid_dpop_proof", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const proof = await makeProof({
      key: dpop,
      htu: "https://evil.example/token", // wrong
      htm: "POST",
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    expect(res.status).toBe(400)
  })

  // ─── case DPOP-7 ── §6.1 refresh preserves DPoP binding ──
  test("DPOP-7. Refreshing a DPoP-bound token requires a matching DPoP proof", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const initialProof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const initial = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/token", {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            dpop: initialProof,
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: "rp-1",
            redirect_uri: "https://app.example/callback",
            code_verifier: verifier,
          }).toString(),
        }),
      )
      .then((r) => r.json())) as TokenResponse

    const refreshToken = initial.refresh_token
    if (!refreshToken) throw new Error("expected refresh_token")

    // First — refresh with NO DPoP proof must fail.
    const noProof = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }).toString(),
      }),
    )
    expect(noProof.status).toBe(400)
    expect(((await noProof.json()) as { error: string }).error).toBe(
      "invalid_dpop_proof",
    )

    // Second — refresh with matching proof succeeds; new token also DPoP-bound.
    const refreshProof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const refreshed = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/token", {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            dpop: refreshProof,
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
          }).toString(),
        }),
      )
      .then((r) => r.json())) as TokenResponse
    expect(refreshed.token_type).toBe("DPoP")
    expect(refreshed.access_token).toBeString()
  })

  // ─── case DPOP-8 ── §6.1 refresh with mismatched key → reject ──
  test("DPOP-8. Refresh with a DIFFERENT DPoP key → invalid_dpop_proof", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const original = await newDpopKey()
    const tokenProof = await makeProof({
      key: original,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const initial = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/token", {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            dpop: tokenProof,
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: "rp-1",
            redirect_uri: "https://app.example/callback",
            code_verifier: verifier,
          }).toString(),
        }),
      )
      .then((r) => r.json())) as TokenResponse
    const attacker = await newDpopKey()
    const stolenProof = await makeProof({
      key: attacker,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const refreshToken = initial.refresh_token
    if (!refreshToken) throw new Error("expected refresh_token")
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: stolenProof,
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }).toString(),
      }),
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_dpop_proof",
    )
  })

  // ─── case DPOP-9 ── §5.2 dpopRequired client rejects Bearer ──
  test("DPOP-9. dpopRequired client + /token without DPoP proof → invalid_dpop_proof", async () => {
    const h = await buildDpopHarness({ dpopRequired: true })
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_dpop_proof",
    )
  })

  // ─── case DPOP-10 ── §5.1 discovery advertises dpop_signing_alg_values_supported ──
  test("DPOP-10. Discovery advertises dpop_signing_alg_values_supported", async () => {
    const h = await buildDpopHarness()
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/.well-known/openid-configuration"),
    )
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.dpop_signing_alg_values_supported).toEqual(["ES256", "EdDSA"])
  })

  // ─── case DPOP-11 ── DPoP scheme presented for plain Bearer token ──
  test("DPOP-11. Plain Bearer token presented via DPoP scheme → invalid_grant", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const bearer = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/token", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: "rp-1",
            redirect_uri: "https://app.example/callback",
            code_verifier: verifier,
          }).toString(),
        }),
      )
      .then((r) => r.json())) as TokenResponse
    expect(bearer.token_type).toBe("Bearer")

    const dpop = await newDpopKey()
    const proof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/userinfo",
      htm: "GET",
      ath: await computeAth(bearer.access_token),
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/userinfo", {
        headers: {
          authorization: `DPoP ${bearer.access_token}`,
          dpop: proof,
        },
      }),
    )
    expect(res.status).toBe(401)
    const err = (await res.json()) as { error: string }
    expect(err.error).toBe("invalid_token")
  })

  // ─── case DPOP-AUDIT ── §11.1 replay emits dpop_replay_detected event ──
  test("DPOP-AUDIT. Replay of jti emits a `dpop_replay_detected` audit event", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const issuerUrl = "https://idp.example"
    const auditLog = new MemoryAuditLog()
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({})
    const tokenStore = new MemoryTokenStore({ keyStore })
    const sessionStore = new MemorySessionStore({})
    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog,
      issuerUrl,
      methods: { stub: redirectFactory({ kind: "stub" }) as never },
      subjects: testSubjects,
      success: async ({ providerSubject }) =>
        ({
          type: "user",
          properties: { userId: providerSubject },
        }) as never,
    })
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const challenge = await s256Challenge(verifier)
    const authorize = await idp.handle(
      new Request(
        authorizeUrl(issuerUrl, {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      ),
    )
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const dpop = await newDpopKey()
    const sharedJti = nextJti()
    const proof = await makeProof({
      key: dpop,
      htu: issuerUrl + "/token",
      htm: "POST",
      jti: sharedJti,
    })
    await idp.handle(
      new Request(issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    // Replay the same proof.
    await idp.handle(
      new Request(issuerUrl + "/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }).toString(),
      }),
    )
    const replays = auditLog.byKind("dpop_replay_detected")
    expect(replays.length).toBe(1)
    expect(replays[0]!.jtiPrefix).toBe(sharedJti.slice(0, 16))
  })

  // ─── case DPOP-12 ── §7 missing ath on RS proof → reject ──
  test("DPOP-12. /userinfo proof without ath claim → invalid_dpop_proof", async () => {
    const h = await buildDpopHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const code = await authorize(h, verifier)
    const dpop = await newDpopKey()
    const tokenProof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/token",
      htm: "POST",
    })
    const body = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/token", {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            dpop: tokenProof,
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: "rp-1",
            redirect_uri: "https://app.example/callback",
            code_verifier: verifier,
          }).toString(),
        }),
      )
      .then((r) => r.json())) as TokenResponse
    // Proof without ath.
    const usinfoProof = await makeProof({
      key: dpop,
      htu: h.issuerUrl + "/userinfo",
      htm: "GET",
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/userinfo", {
        headers: {
          authorization: `DPoP ${body.access_token}`,
          dpop: usinfoProof,
        },
      }),
    )
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_dpop_proof",
    )
  })
})
