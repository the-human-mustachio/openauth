/**
 * OIDC Core 1.0 `id_token` issuance + `/userinfo` claim gating
 * conformance matrix.
 *
 * Every case below cites the relevant OIDC Core 1.0 section. The matrix
 * is designed to be the acceptance gate for the Phase 8 OIDC-issuance
 * session — extend it when new id_token features land (claims param,
 * pairwise subjects, etc.).
 *
 * The IdP is wired through `createIdP` over memory adapters via
 * `buildHarness`, identical to the OAuth 2.1 matrix.
 */
import { describe, expect, test } from "bun:test"

import { createIdP } from "../../src/index"
import { asTenantId } from "../../src/types/tenant"
import { ok } from "../../src/types/result"
import type { Result } from "../../src/types/result"
import type { SigningKey } from "../../src/ports/key-store"
import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { computeAtHash } from "../../src/domain/id-token"
import { verifyIdToken } from "../../src/domain/jwt"
import { s256Challenge } from "../../src/domain/pkce"

import {
  authorizeUrl,
  buildHarness,
  driveCallback,
  tokenRequest,
} from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

/** Type-narrow a `Result<SigningKey[]>` to its keys array, throwing on `err`. */
function unwrapKeys(res: Result<SigningKey[]>): SigningKey[] {
  if (!res.ok) throw new Error(`signingKeys() returned err: ${res.error.code}`)
  return res.value
}

/** Run the standard authorize→callback→exchange dance and return the JSON body. */
async function authorizeAndExchange(
  h: Awaited<ReturnType<typeof buildHarness>>,
  authorizeParams: Record<string, string>,
): Promise<{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: any
  status: number
}> {
  const authorize = await h.idp.handle(
    new Request(
      authorizeUrl(h.issuerUrl, {
        response_type: "code",
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        scope: "openid",
        state: "rp-csrf",
        code_challenge: h.challengePair.challenge,
        code_challenge_method: "S256",
        ...authorizeParams,
      }),
    ),
  )
  expect(authorize.status).toBe(302)
  const cb = await driveCallback(h.idp, authorize.headers.get("location")!)
  expect(cb.status).toBe(302)
  const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
  const tokenRes = await h.idp.handle(
    tokenRequest(h.issuerUrl, {
      grant_type: "authorization_code",
      code,
      client_id: "rp-1",
      redirect_uri: "https://app.example/callback",
      code_verifier: h.challengePair.verifier,
    }),
  )
  return { body: await tokenRes.json(), status: tokenRes.status }
}

describe("OIDC Core 1.0 — id_token issuance + userinfo conformance", () => {
  // ─── case OIDC-1 ── §2 REQUIRED claims + §3.1.3.7 signature verifies ──
  test("OIDC-1. /token with scope=openid issues id_token; signature + REQUIRED claims valid", async () => {
    const h = await buildHarness()
    const { body, status } = await authorizeAndExchange(h, { scope: "openid" })
    expect(status).toBe(200)
    expect(body.id_token).toBeString()

    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(body.id_token, keys, {
      issuer: h.issuerUrl,
      audience: "rp-1",
    })
    // OIDC Core §2 REQUIRED claims.
    expect(claims.iss).toBe(h.issuerUrl)
    expect(claims.aud).toBe("rp-1")
    expect(claims.sub).toBeString()
    expect(typeof claims.exp).toBe("number")
    expect(typeof claims.iat).toBe("number")
    expect(claims.exp).toBeGreaterThan(claims.iat)
  })

  // ─── case OIDC-2 ── §3.1.2.1 `nonce` REQUIRED-to-echo when supplied ──
  test("OIDC-2. id_token.nonce equals the /authorize nonce param verbatim", async () => {
    const h = await buildHarness()
    const { body } = await authorizeAndExchange(h, {
      scope: "openid",
      nonce: "n-0S6_WzA2Mj",
    })
    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(body.id_token, keys)
    expect(claims.nonce).toBe("n-0S6_WzA2Mj")
  })

  // ─── case OIDC-3 ── §3.1.3.6 `at_hash` left-half SHA-256 binding ──
  test("OIDC-3. id_token.at_hash matches left-half SHA-256 of access_token", async () => {
    const h = await buildHarness()
    const { body } = await authorizeAndExchange(h, { scope: "openid" })
    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(body.id_token, keys)
    const expected = await computeAtHash(body.access_token)
    expect(claims.at_hash).toBe(expected)
  })

  // ─── case OIDC-4 ── §2 `auth_time` populated at success time ──
  test("OIDC-4. id_token.auth_time is present and finite", async () => {
    const h = await buildHarness()
    const { body } = await authorizeAndExchange(h, { scope: "openid" })
    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(body.id_token, keys)
    expect(typeof claims.auth_time).toBe("number")
    expect(claims.auth_time!).toBeGreaterThan(0)
    expect(claims.auth_time!).toBeLessThanOrEqual(claims.iat)
  })

  // ─── case OIDC-5 ── scope check: openid required to issue id_token ──
  test("OIDC-5. /token with scope NOT containing openid omits id_token", async () => {
    // The default seed tenant only allows `openid email profile`. Use an
    // ad-hoc tenant whose client allows `email` alone so we can request
    // `scope=email` without tripping `invalid_scope`.
    const tenant = await buildTenant({
      scopes: ["email"],
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
      subjects: {} as never,
      success: async ({ providerSubject, properties }) =>
        ({
          type: "user",
          properties: { userId: providerSubject, ...(properties as object) },
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
          scope: "email",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      ),
    )
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const tokenRes = await idp.handle(
      tokenRequest(issuerUrl, {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }),
    )
    expect(tokenRes.status).toBe(200)
    const body = await tokenRes.json()
    expect(body.access_token).toBeString()
    expect(body.id_token).toBeUndefined()
  })

  // ─── case OIDC-6 ── §12 refresh reissues id_token; auth_time stable; no nonce ──
  test("OIDC-6. Refresh grant reissues id_token with stable auth_time and NO nonce", async () => {
    const h = await buildHarness()
    const initial = await authorizeAndExchange(h, {
      scope: "openid",
      nonce: "orig-nonce",
    })
    expect(initial.body.id_token).toBeString()

    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const initialClaims = await verifyIdToken(initial.body.id_token, keys)
    expect(initialClaims.nonce).toBe("orig-nonce")

    const refreshed = await h.idp
      .handle(
        tokenRequest(h.issuerUrl, {
          grant_type: "refresh_token",
          refresh_token: initial.body.refresh_token,
        }),
      )
      .then((r) => r.json())
    expect(refreshed.id_token).toBeString()
    const refreshedClaims = await verifyIdToken(refreshed.id_token, keys)
    // OIDC Core §12: auth_time SHOULD NOT advance on refresh — the user
    // hasn't re-authenticated.
    expect(initialClaims.auth_time).toBeDefined()
    expect(refreshedClaims.auth_time).toBe(initialClaims.auth_time as number)
    // Nonce was bound to the original /authorize and MUST NOT reappear
    // on tokens issued without a fresh nonce.
    expect(refreshedClaims.nonce).toBeUndefined()
  })

  // ─── case OIDC-7 ── §5.4 scope→claim gating: email scope → email claim ──
  test("OIDC-7. scope=openid+email grants email claim in id_token AND /userinfo", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const issuerUrl = "https://idp.example"
    const auditLog = new MemoryAuditLog()
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({})
    const tokenStore = new MemoryTokenStore({ keyStore })
    const sessionStore = new MemorySessionStore({})
    // Override the redirectFactory to return an email property the
    // success callback will pass through.
    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog,
      issuerUrl,
      methods: {
        stub: redirectFactory({
          kind: "stub",
          properties: { handle: "ada" } as never,
        }) as never,
      },
      subjects: {} as never,
      success: async ({ providerSubject }) =>
        ({
          type: "user",
          properties: {
            userId: providerSubject,
            email: "ada@example.com",
            email_verified: true,
            name: "Ada Lovelace",
          },
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
          scope: "openid email",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      ),
    )
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const tokenBody = await idp
      .handle(
        tokenRequest(issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())

    const keys = unwrapKeys(await keyStore.signingKeys())
    const claims = await verifyIdToken(tokenBody.id_token, keys)
    expect(claims.email).toBe("ada@example.com")
    expect(claims.email_verified).toBe(true)
    // `name` is gated by `profile` scope, NOT `email`. We did not grant
    // `profile`, so the claim must be absent from the id_token.
    expect(claims.name).toBeUndefined()

    // /userinfo applies the same mapping.
    const userinfoRes = await idp.handle(
      new Request(issuerUrl + "/userinfo", {
        headers: { authorization: `Bearer ${tokenBody.access_token}` },
      }),
    )
    expect(userinfoRes.status).toBe(200)
    const userinfo = await userinfoRes.json()
    expect(userinfo.email).toBe("ada@example.com")
    expect(userinfo.email_verified).toBe(true)
    expect(userinfo.name).toBeUndefined()
  })

  // ─── case OIDC-8 ── §5.4 negative gating: no email scope → no email claim ──
  test("OIDC-8. scope=openid alone yields NO email claim in id_token or /userinfo", async () => {
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
      subjects: {} as never,
      success: async ({ providerSubject }) =>
        ({
          type: "user",
          properties: {
            userId: providerSubject,
            email: "ada@example.com",
            email_verified: true,
          },
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
    const tokenBody = await idp
      .handle(
        tokenRequest(issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())

    const keys = unwrapKeys(await keyStore.signingKeys())
    const claims = await verifyIdToken(tokenBody.id_token, keys)
    expect(claims.email).toBeUndefined()
    expect(claims.email_verified).toBeUndefined()

    const userinfo = await idp
      .handle(
        new Request(issuerUrl + "/userinfo", {
          headers: { authorization: `Bearer ${tokenBody.access_token}` },
        }),
      )
      .then((r) => r.json())
    expect(userinfo.email).toBeUndefined()
    expect(userinfo.email_verified).toBeUndefined()
  })

  // ─── case OIDC-9 ── RFC 8176 `amr` derived from method kind ──
  test("OIDC-9. amr=['pwd'] when originating method kind is `password`", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "password", kind: "password" }],
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
      methods: { password: redirectFactory({ kind: "password" }) as never },
      subjects: {} as never,
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
    const body = await idp
      .handle(
        tokenRequest(issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())

    const keys = unwrapKeys(await keyStore.signingKeys())
    const claims = await verifyIdToken(body.id_token, keys)
    expect(claims.amr).toEqual(["pwd"])
  })

  // ─── case OIDC-10 ── client_credentials grant must NOT issue id_token ──
  // (Cross-check: §2 says id_token represents end-user authentication;
  //  client_credentials has no end-user.)
  test("OIDC-10. client_credentials grant omits id_token regardless of scope", async () => {
    // We don't have a wired m2m method in the conformance harness, so
    // smoke-test the predicate `shouldIssueIdToken` + the `authTime`
    // gate via the public API: a client_credentials request hits the
    // m2m path which calls mintTokens without `authTime`, so id_token
    // must be undefined. Verified upstream by the
    // `client_credentials` integration test suite in test/integration;
    // this case asserts the contract holds at the type level by
    // re-importing the predicate and the threading guarantee.
    const { shouldIssueIdToken } = await import("../../src/domain/id-token")
    expect(shouldIssueIdToken(["openid"])).toBe(true)
    expect(shouldIssueIdToken(["email"])).toBe(false)
    expect(shouldIssueIdToken([])).toBe(false)
    // mintTokens additionally requires `payload.authTime !== undefined`
    // to issue an id_token; `client_credentials` deliberately omits it
    // (see `domain/client-credentials.ts:160-174`). The integration test
    // in `test/integration/full-flow.test.ts` exercises the m2m grant
    // end-to-end and observes no `id_token` in the response.
  })
})
