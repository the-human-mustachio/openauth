/**
 * Phase 8 OIDC polish conformance — discovery metadata, introspect
 * enrichment, claims parameter, pairwise subjects, dynamic client
 * registration, audit-event additions.
 *
 * Each section cites the relevant spec. Features land incrementally;
 * cases here grow as Phase E proceeds.
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

import {
  authorizeUrl,
  driveCallback,
  tokenRequest,
} from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

import type { TokenResponse } from "../../src/types/token"

async function buildConfidentialHarness() {
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
    success: async ({ providerSubject }) =>
      ({
        type: "user",
        properties: { userId: providerSubject },
      }) as never,
  })
  return { idp, issuerUrl }
}

describe("OIDC Discovery — extended metadata", () => {
  // ─── case POLISH-DISC-1 ── §3 claims_supported lists every issuable claim ──
  test("POLISH-DISC-1. Discovery advertises claims_supported with §5.1 fields", async () => {
    const h = await buildConfidentialHarness()
    const doc = (await h.idp
      .handle(new Request(h.issuerUrl + "/.well-known/openid-configuration"))
      .then((r) => r.json())) as Record<string, unknown>
    const claims = doc.claims_supported as string[]
    expect(Array.isArray(claims)).toBe(true)
    // OIDC Core §2 + §5.1 — every claim names something we can return.
    for (const required of [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "amr",
      "at_hash",
      "email",
      "email_verified",
      "name",
      "preferred_username",
    ]) {
      expect(claims).toContain(required)
    }
  })

  // ─── case POLISH-DISC-2 ── §5.5 claims_parameter_supported ──
  test("POLISH-DISC-2. Discovery sets claims_parameter_supported=true", async () => {
    const h = await buildConfidentialHarness()
    const doc = (await h.idp
      .handle(new Request(h.issuerUrl + "/.well-known/openid-configuration"))
      .then((r) => r.json())) as Record<string, unknown>
    expect(doc.claims_parameter_supported).toBe(true)
  })

  // ─── case POLISH-DISC-3 ── §6 request_*_supported flags false ──
  test("POLISH-DISC-3. Discovery sets request_parameter_supported and request_uri_parameter_supported false", async () => {
    const h = await buildConfidentialHarness()
    const doc = (await h.idp
      .handle(new Request(h.issuerUrl + "/.well-known/openid-configuration"))
      .then((r) => r.json())) as Record<string, unknown>
    expect(doc.request_parameter_supported).toBe(false)
    expect(doc.request_uri_parameter_supported).toBe(false)
    expect(doc.require_request_uri_registration).toBe(false)
  })

  // ─── case POLISH-DISC-4 ── §3.1.2.1 ui_locales_supported ──
  test("POLISH-DISC-4. Discovery advertises ui_locales_supported", async () => {
    const h = await buildConfidentialHarness()
    const doc = (await h.idp
      .handle(new Request(h.issuerUrl + "/.well-known/openid-configuration"))
      .then((r) => r.json())) as Record<string, unknown>
    expect(Array.isArray(doc.ui_locales_supported)).toBe(true)
    expect(doc.ui_locales_supported).toEqual(["en"])
  })
})

describe("RFC 7662 — /introspect enrichment", () => {
  // ─── case POLISH-INTRO-1 ── §2.2 token_type indicator ──
  test("POLISH-INTRO-1. Active introspection result includes token_type=Bearer", async () => {
    const h = await buildConfidentialHarness()
    // Issue a token through the normal flow.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const challenge = await s256Challenge(verifier)
    const authorizeRes = await h.idp.handle(
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
    const cb = await driveCallback(h.idp, authorizeRes.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const secretHash = await hashClientSecret("secret-1")
    expect(secretHash).toBeString()
    const tokens = (await h.idp
      .handle(
        tokenRequest(h.issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          client_secret: "secret-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())) as TokenResponse

    const introspectRes = await h.idp.handle(
      new Request(h.issuerUrl + "/introspect", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: tokens.access_token,
          client_id: "rp-1",
          client_secret: "secret-1",
        }).toString(),
      }),
    )
    expect(introspectRes.status).toBe(200)
    const body = (await introspectRes.json()) as Record<string, unknown>
    expect(body.active).toBe(true)
    expect(body.token_type).toBe("Bearer")
    expect(body.subject_type).toBe("user")
    // No DPoP binding on this access token → no cnf in the response.
    expect(body.cnf).toBeUndefined()
  })
})
