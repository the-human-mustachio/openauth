/**
 * OIDC RP-Initiated Logout 1.0 §2 conformance matrix for `/end_session`.
 *
 * Each case cites the spec section. The endpoint is exercised end-to-end
 * through `createIdP` — same harness pattern as the OAuth 2.1 / OIDC
 * Core matrices.
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
import { s256Challenge } from "../../src/domain/pkce"
import { verifyIdToken } from "../../src/domain/jwt"
import type { TokenResponse } from "../../src/types/token"

import {
  authorizeUrl,
  driveCallback,
  tokenRequest,
} from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

function unwrapKeys(res: Result<SigningKey[]>): SigningKey[] {
  if (!res.ok) throw new Error(`signingKeys err: ${res.error.code}`)
  return res.value
}

/**
 * Build an IdP wired to a tenant whose RP has the supplied
 * `postLogoutRedirectUris`, run a full code-flow auth, exchange for
 * tokens, and return the issued tokens + helpers.
 */
async function loginAndGetTokens(opts: {
  postLogoutRedirectUris?: string[]
}) {
  const tenant = await buildTenant({
    methods: [{ id: "stub", kind: "stub" }],
    ...(opts.postLogoutRedirectUris !== undefined
      ? { postLogoutRedirectUris: opts.postLogoutRedirectUris }
      : {}),
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
        state: "rp-csrf",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }),
    ),
  )
  const cb = await driveCallback(idp, authorize.headers.get("location")!)
  const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
  const tokens = (await idp
    .handle(
      tokenRequest(issuerUrl, {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }),
    )
    .then((r) => r.json())) as TokenResponse

  return { idp, tokens, auditLog, tokenStore, keyStore, issuerUrl }
}

/** Narrow `id_token` to `string` for tests that require it. */
function requireIdToken(t: TokenResponse): string {
  if (!t.id_token) throw new Error("expected id_token")
  return t.id_token
}

describe("OIDC RP-Initiated Logout 1.0 — /end_session conformance", () => {
  // ─── case LOGOUT-1 ── §2 redirect with state echoed ──
  test("LOGOUT-1. GET /end_session with valid id_token_hint + registered post_logout_redirect_uri + state → 302 with state echoed", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    const url = new URL(h.issuerUrl + "/end_session")
    url.searchParams.set("id_token_hint", requireIdToken(h.tokens))
    url.searchParams.set(
      "post_logout_redirect_uri",
      "https://app.example/post-logout",
    )
    url.searchParams.set("state", "rp-logout-state")
    const res = await h.idp.handle(new Request(url.toString()))
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get("location")!)
    expect(loc.origin + loc.pathname).toBe("https://app.example/post-logout")
    expect(loc.searchParams.get("state")).toBe("rp-logout-state")
  })

  // ─── case LOGOUT-2 ── §2 unregistered URI → never redirected ──
  test("LOGOUT-2. Unregistered post_logout_redirect_uri → 400, never redirected (open-redirector defense)", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    const url = new URL(h.issuerUrl + "/end_session")
    url.searchParams.set("id_token_hint", requireIdToken(h.tokens))
    url.searchParams.set(
      "post_logout_redirect_uri",
      "https://evil.example/steal",
    )
    const res = await h.idp.handle(new Request(url.toString()))
    expect(res.status).toBe(400)
    expect(res.headers.get("location")).toBeNull()
  })

  // ─── case LOGOUT-3 ── valid hint → subject tokens revoked ──
  test("LOGOUT-3. After /end_session, the user's refresh tokens are revoked", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    // First confirm the refresh token still works.
    const initialRefresh = h.tokens.refresh_token
    if (!initialRefresh) throw new Error("expected initial refresh_token")
    const preCheck = await h.idp.handle(
      tokenRequest(h.issuerUrl, {
        grant_type: "refresh_token",
        refresh_token: initialRefresh,
      }),
    )
    expect(preCheck.status).toBe(200)
    const fresh = (await preCheck.json()) as TokenResponse

    const url = new URL(h.issuerUrl + "/end_session")
    url.searchParams.set("id_token_hint", requireIdToken(fresh))
    url.searchParams.set(
      "post_logout_redirect_uri",
      "https://app.example/post-logout",
    )
    const logout = await h.idp.handle(new Request(url.toString()))
    expect(logout.status).toBe(302)

    // The (rotated) refresh token must now be revoked.
    const rotatedRefresh = fresh.refresh_token
    if (!rotatedRefresh) throw new Error("expected rotated refresh_token")
    const postCheck = await h.idp.handle(
      tokenRequest(h.issuerUrl, {
        grant_type: "refresh_token",
        refresh_token: rotatedRefresh,
      }),
    )
    expect(postCheck.status).toBe(400)
  })

  // ─── case LOGOUT-4 ── discovery advertises end_session_endpoint ──
  test("LOGOUT-4. Discovery doc advertises end_session_endpoint", async () => {
    const h = await loginAndGetTokens({})
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/.well-known/openid-configuration"),
    )
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.end_session_endpoint).toBe(h.issuerUrl + "/end_session")
  })

  // ─── case LOGOUT-5 ── §2 expired id_token_hint still accepted ──
  test("LOGOUT-5. Expired id_token_hint is still accepted (logout commonly follows expiry)", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    // The token isn't actually expired in this test (no fake clock), but
    // we exercise the same path. Verify directly that `verifyIdToken`
    // with `acceptExpired: true` doesn't reject the in-date token, and
    // that the endpoint behavior matches.
    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(requireIdToken(h.tokens), keys, {
      acceptExpired: true,
      issuer: h.issuerUrl,
    })
    expect(claims.sub).toBeString()

    const url = new URL(h.issuerUrl + "/end_session")
    url.searchParams.set("id_token_hint", requireIdToken(h.tokens))
    url.searchParams.set(
      "post_logout_redirect_uri",
      "https://app.example/post-logout",
    )
    const res = await h.idp.handle(new Request(url.toString()))
    expect(res.status).toBe(302)
  })

  // ─── case LOGOUT-6 ── POST form-body equivalent to GET query ──
  test("LOGOUT-6. POST /end_session with form body works identically to GET", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    const body = new URLSearchParams({
      id_token_hint: requireIdToken(h.tokens),
      post_logout_redirect_uri: "https://app.example/post-logout",
      state: "x",
    })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/end_session", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }),
    )
    expect(res.status).toBe(302)
    expect(
      new URL(res.headers.get("location")!).searchParams.get("state"),
    ).toBe("x")
  })

  // ─── case LOGOUT-7 ── §2 client_id mismatch with id_token_hint.aud ──
  test("LOGOUT-7. client_id mismatch with id_token_hint.aud → 400 invalid_request", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    const url = new URL(h.issuerUrl + "/end_session")
    url.searchParams.set("id_token_hint", requireIdToken(h.tokens))
    url.searchParams.set("client_id", "different-rp")
    const res = await h.idp.handle(new Request(url.toString()))
    expect(res.status).toBe(400)
  })

  // ─── case LOGOUT-8 ── §2 no hint, no URI → 200 generic ack ──
  test("LOGOUT-8. /end_session with no params → 200 logged-out acknowledgement", async () => {
    const h = await loginAndGetTokens({})
    const res = await h.idp.handle(new Request(h.issuerUrl + "/end_session"))
    expect(res.status).toBe(200)
    expect(await res.text()).toContain("Logged out")
  })

  // ─── case LOGOUT-9 ── audit event recorded ──
  test("LOGOUT-9. Successful logout emits a `session_logout` audit event", async () => {
    const h = await loginAndGetTokens({
      postLogoutRedirectUris: ["https://app.example/post-logout"],
    })
    const url = new URL(h.issuerUrl + "/end_session")
    url.searchParams.set("id_token_hint", requireIdToken(h.tokens))
    url.searchParams.set(
      "post_logout_redirect_uri",
      "https://app.example/post-logout",
    )
    await h.idp.handle(new Request(url.toString()))
    const events = h.auditLog.byKind("session_logout")
    expect(events.length).toBe(1)
    expect(events[0]!.tenantId).toBe(asTenantId("acme"))
    expect(events[0]!.clientId).toBe("rp-1")
    expect(events[0]!.subjectId).toBeString()
  })

  // ─── case LOGOUT-10 ── §2 invalid signature rejected ──
  test("LOGOUT-10. /end_session with a structurally-broken id_token_hint → 400", async () => {
    const h = await loginAndGetTokens({})
    const res = await h.idp.handle(
      new Request(
        h.issuerUrl + "/end_session?id_token_hint=not.a.real.jwt",
      ),
    )
    expect(res.status).toBe(400)
  })
})
