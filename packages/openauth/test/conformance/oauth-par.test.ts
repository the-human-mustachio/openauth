/**
 * RFC 9126 — Pushed Authorization Requests conformance matrix.
 *
 * Each case cites the relevant section. The endpoint is exercised
 * end-to-end through `createIdP` so the `/par` → `/authorize` rehydrate
 * round-trip is verified against the real Hono router.
 */
import { describe, expect, test } from "bun:test"

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
import { hashClientSecret } from "../../src/domain/token"
import { PAR_URI_PREFIX } from "../../src/domain/par"

import { authorizeUrl, driveCallback } from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

async function buildPublicHarness(
  opts: {
    requirePar?: boolean
  } = {},
) {
  const tenant = await buildTenant({
    methods: [{ id: "stub", kind: "stub" }],
  })
  // Apply requirePar override directly to the seed config.
  if (opts.requirePar) {
    ;(
      tenant.clients[0] as { requirePushedAuthorizationRequests?: boolean }
    ).requirePushedAuthorizationRequests = true
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
    subjects: {} as never,
    success: async ({ providerSubject }) =>
      ({
        type: "user",
        properties: { userId: providerSubject },
      }) as never,
  })
  return { idp, issuerUrl, sessionStore }
}

function parRequest(
  base: string,
  body: Record<string, string>,
  authHeader?: string,
): Request {
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
  }
  if (authHeader) headers.authorization = authHeader
  return new Request(base + "/par", {
    method: "POST",
    headers,
    body: new URLSearchParams(body).toString(),
  })
}

describe("RFC 9126 — Pushed Authorization Requests conformance", () => {
  // ─── case PAR-1 ── §3 happy-path: 201 + request_uri + expires_in ──
  test("PAR-1. POST /par with valid params → 201 with request_uri (urn:…) and expires_in", async () => {
    const h = await buildPublicHarness()
    const challenge = await s256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    const res = await h.idp.handle(
      parRequest(h.issuerUrl, {
        response_type: "code",
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        scope: "openid",
        state: "rp-csrf",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }),
    )
    expect(res.status).toBe(201)
    const body = (await res.json()) as {
      request_uri: string
      expires_in: number
    }
    expect(body.request_uri).toBeString()
    expect(body.request_uri.startsWith(PAR_URI_PREFIX)).toBe(true)
    expect(typeof body.expires_in).toBe("number")
    expect(body.expires_in).toBeGreaterThan(0)
  })

  // ─── case PAR-2 ── §4 /authorize?request_uri=... rehydrates and proceeds ──
  test("PAR-2. /authorize?client_id=...&request_uri=... → 302 upstream (rehydrate succeeds)", async () => {
    const h = await buildPublicHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const challenge = await s256Challenge(verifier)
    const par = await h.idp
      .handle(
        parRequest(h.issuerUrl, {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "rp-csrf",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      )
      .then((r) => r.json())

    const authorize = await h.idp.handle(
      new Request(
        authorizeUrl(h.issuerUrl, {
          client_id: "rp-1",
          request_uri: par.request_uri,
        }),
      ),
    )
    expect(authorize.status).toBe(302)
    const loc = authorize.headers.get("location")!
    expect(loc.startsWith("https://upstream.example/auth")).toBe(true)

    // Carrying the flow through callback proves the rehydrated params
    // (scope, redirect_uri, state, PKCE) were honored end-to-end.
    const cb = await driveCallback(h.idp, loc)
    expect(cb.status).toBe(302)
    const cbLoc = new URL(cb.headers.get("location")!)
    expect(cbLoc.origin + cbLoc.pathname).toBe("https://app.example/callback")
    expect(cbLoc.searchParams.get("state")).toBe("rp-csrf")
  })

  // ─── case PAR-3 ── §4 one-shot: second /authorize with same request_uri fails ──
  test("PAR-3. request_uri is one-shot — second use → invalid_request", async () => {
    const h = await buildPublicHarness()
    const challenge = await s256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    const par = await h.idp
      .handle(
        parRequest(h.issuerUrl, {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      )
      .then((r) => r.json())

    const first = await h.idp.handle(
      new Request(
        authorizeUrl(h.issuerUrl, {
          client_id: "rp-1",
          request_uri: par.request_uri,
        }),
      ),
    )
    expect(first.status).toBe(302)

    const second = await h.idp.handle(
      new Request(
        authorizeUrl(h.issuerUrl, {
          client_id: "rp-1",
          request_uri: par.request_uri,
        }),
      ),
    )
    expect(second.status).toBe(400)
    expect(await second.text()).toContain("invalid_request")
  })

  // ─── case PAR-4 ── §2 confidential client without secret → invalid_client ──
  test("PAR-4. Confidential client without credentials → invalid_client", async () => {
    const tenant = await buildTenant({
      clientType: "confidential",
      clientSecretPlain: "secret-1",
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
      success: async () => ({ type: "user", properties: {} }) as never,
    })

    const challenge = await s256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    const res = await idp.handle(
      parRequest(issuerUrl, {
        response_type: "code",
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        scope: "openid",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }),
    )
    // RFC 6749 §5.2: `invalid_client` is the only OAuth error that
    // returns HTTP 401 (with WWW-Authenticate). The framework maps it
    // accordingly via `tokenEndpointErrorResponse`.
    expect(res.status).toBe(401)
    const errBody = (await res.json()) as { error: string }
    expect(errBody.error).toBe("invalid_client")
    // Sanity: include hash here so the variable isn't dead.
    expect(await hashClientSecret("secret-1")).toBeString()
  })

  // ─── case PAR-5 ── per-client require_par enforcement ──
  test("PAR-5. require_par=true + direct /authorize → invalid_request", async () => {
    const h = await buildPublicHarness({ requirePar: true })
    const challenge = await s256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    const res = await h.idp.handle(
      new Request(
        authorizeUrl(h.issuerUrl, {
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
    expect(res.status).toBe(400)
    expect(await res.text()).toContain("invalid_request")
  })

  // ─── case PAR-6 ── per-client require_par via PAR still works ──
  test("PAR-6. require_par=true + /authorize?request_uri=... → succeeds", async () => {
    const h = await buildPublicHarness({ requirePar: true })
    const challenge = await s256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    const par = await h.idp
      .handle(
        parRequest(h.issuerUrl, {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      )
      .then((r) => r.json())
    const res = await h.idp.handle(
      new Request(
        authorizeUrl(h.issuerUrl, {
          client_id: "rp-1",
          request_uri: par.request_uri,
        }),
      ),
    )
    expect(res.status).toBe(302)
  })

  // ─── case PAR-7 ── §5 discovery advertises endpoint ──
  test("PAR-7. Discovery advertises pushed_authorization_request_endpoint", async () => {
    const h = await buildPublicHarness()
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/.well-known/openid-configuration"),
    )
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.pushed_authorization_request_endpoint).toBe(h.issuerUrl + "/par")
    expect(doc.require_pushed_authorization_requests).toBe(false)
  })

  // ─── case PAR-8 ── §4 client_id mismatch between /par and /authorize ──
  test("PAR-8. /authorize?client_id=other&request_uri=... → invalid_request", async () => {
    const h = await buildPublicHarness()
    const challenge = await s256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    const par = await h.idp
      .handle(
        parRequest(h.issuerUrl, {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      )
      .then((r) => r.json())
    const res = await h.idp.handle(
      new Request(
        authorizeUrl(h.issuerUrl, {
          client_id: "different",
          request_uri: par.request_uri,
        }),
      ),
    )
    expect(res.status).toBe(400)
  })

  // ─── case PAR-9 ── §2.1 request_uri MUST NOT appear in PAR body ──
  test("PAR-9. POST /par with request_uri in body → invalid_request", async () => {
    const h = await buildPublicHarness()
    const res = await h.idp.handle(
      parRequest(h.issuerUrl, {
        response_type: "code",
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        request_uri: "urn:ietf:params:oauth:request_uri:should-not-be-here",
      }),
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_request",
    )
  })
})
