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
import { verifyIdToken } from "../../src/domain/jwt"
import type { Result } from "../../src/types/result"
import type { SigningKey } from "../../src/ports/key-store"

import {
  authorizeUrl,
  driveCallback,
  tokenRequest,
} from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

import type { TokenResponse } from "../../src/types/token"

function unwrapKeys(res: Result<SigningKey[]>): SigningKey[] {
  if (!res.ok) throw new Error(`signingKeys err: ${res.error.code}`)
  return res.value
}

function requireIdToken(body: TokenResponse): string {
  if (!body.id_token) throw new Error("expected id_token")
  return body.id_token
}

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

describe("OIDC Core §5.5 — claims parameter", () => {
  async function buildClaimsHarness() {
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
            name: "Ada Lovelace",
          },
        }) as never,
    })
    return { idp, issuerUrl, keyStore }
  }

  // ─── case POLISH-CLAIMS-1 ── §5.5 id_token claims-parameter bypasses scope ──
  test("POLISH-CLAIMS-1. claims={id_token:{email:null}} grants email even without email scope", async () => {
    const h = await buildClaimsHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const challenge = await s256Challenge(verifier)
    const claimsParam = JSON.stringify({ id_token: { email: null } })
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
          claims: claimsParam,
        }),
      ),
    )
    expect(authorizeRes.status).toBe(302)
    const cb = await driveCallback(h.idp, authorizeRes.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const tokens = (await h.idp
      .handle(
        tokenRequest(h.issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())) as TokenResponse
    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(requireIdToken(tokens), keys)
    expect(claims.email).toBe("ada@example.com")
    // We asked only for `email` in id_token — `name` (profile-scoped) stays absent.
    expect(claims.name).toBeUndefined()
  })

  // ─── case POLISH-CLAIMS-2 ── §5.5 userinfo claims-parameter bypasses scope ──
  test("POLISH-CLAIMS-2. claims={userinfo:{name:null}} grants name on /userinfo", async () => {
    const h = await buildClaimsHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const challenge = await s256Challenge(verifier)
    const claimsParam = JSON.stringify({ userinfo: { name: null } })
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
          claims: claimsParam,
        }),
      ),
    )
    const cb = await driveCallback(h.idp, authorizeRes.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const tokens = (await h.idp
      .handle(
        tokenRequest(h.issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())) as TokenResponse
    const userinfoRes = await h.idp.handle(
      new Request(h.issuerUrl + "/userinfo", {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      }),
    )
    expect(userinfoRes.status).toBe(200)
    const userinfo = (await userinfoRes.json()) as Record<string, unknown>
    // `name` would normally require the `profile` scope; the claims
    // parameter overrides that.
    expect(userinfo.name).toBe("Ada Lovelace")
    // `email` was NOT requested via claims and `email` scope wasn't granted.
    expect(userinfo.email).toBeUndefined()
  })

  // ─── case POLISH-CLAIMS-3 ── malformed claims JSON → invalid_request ──
  test("POLISH-CLAIMS-3. claims=<bad-json> → 400 invalid_request", async () => {
    const h = await buildClaimsHarness()
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
          claims: "{not-json",
        }),
      ),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toContain("invalid_request")
  })

  // ─── case POLISH-CLAIMS-4 ── §12 refresh preserves claims-parameter intent ──
  test("POLISH-CLAIMS-4. Refresh-grant id_token retains email requested via claims parameter", async () => {
    const h = await buildClaimsHarness()
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const challenge = await s256Challenge(verifier)
    const claimsParam = JSON.stringify({ id_token: { email: null } })
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
          claims: claimsParam,
        }),
      ),
    )
    const cb = await driveCallback(h.idp, authorizeRes.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const initial = (await h.idp
      .handle(
        tokenRequest(h.issuerUrl, {
          grant_type: "authorization_code",
          code,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      .then((r) => r.json())) as TokenResponse
    if (!initial.refresh_token) throw new Error("expected refresh_token")
    const refreshed = (await h.idp
      .handle(
        tokenRequest(h.issuerUrl, {
          grant_type: "refresh_token",
          refresh_token: initial.refresh_token,
        }),
      )
      .then((r) => r.json())) as TokenResponse
    const keys = unwrapKeys(await h.keyStore.signingKeys())
    const claims = await verifyIdToken(requireIdToken(refreshed), keys)
    expect(claims.email).toBe("ada@example.com")
  })
})

describe("OIDC Core §8.1 — pairwise subjects", () => {
  // ─── case POLISH-PAIRWISE-1 ── public sub is identical across clients ──
  test("POLISH-PAIRWISE-1. Two clients without sectorIdentifier produce the same sub for the same end user", async () => {
    // Build a tenant with two clients, both public-subject.
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    // Add a second client that mirrors rp-1 but has its own id.
    tenant.clients.push({
      id: "rp-2",
      name: "Test RP 2",
      type: "public",
      redirectUris: ["https://app2.example/callback"],
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["openid"],
      pkceRequired: true,
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
      success: async () =>
        ({
          type: "user",
          properties: { userId: "stable-user-1" },
        }) as never,
    })

    const subFor = async (clientId: string, redirectUri: string) => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      const challenge = await s256Challenge(verifier)
      const authorizeRes = await idp.handle(
        new Request(
          authorizeUrl(issuerUrl, {
            response_type: "code",
            client_id: clientId,
            redirect_uri: redirectUri,
            scope: "openid",
            state: "s",
            code_challenge: challenge,
            code_challenge_method: "S256",
          }),
        ),
      )
      const cb = await driveCallback(idp, authorizeRes.headers.get("location")!)
      const code = new URL(cb.headers.get("location")!).searchParams.get(
        "code",
      )!
      const tokens = (await idp
        .handle(
          tokenRequest(issuerUrl, {
            grant_type: "authorization_code",
            code,
            client_id: clientId,
            redirect_uri: redirectUri,
            code_verifier: verifier,
          }),
        )
        .then((r) => r.json())) as TokenResponse
      const keys = unwrapKeys(await keyStore.signingKeys())
      const claims = await verifyIdToken(requireIdToken(tokens), keys)
      return claims.sub
    }

    const sub1 = await subFor("rp-1", "https://app.example/callback")
    const sub2 = await subFor("rp-2", "https://app2.example/callback")
    expect(sub1).toBe(sub2)
  })

  // ─── case POLISH-PAIRWISE-2 ── different sectorIdentifier → different sub ──
  test("POLISH-PAIRWISE-2. Two clients with different sectorIdentifier produce different sub for the same end user", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    // Apply distinct sectorIdentifier to rp-1 + add rp-2 with another.
    ;(tenant.clients[0] as { sectorIdentifier?: string }).sectorIdentifier =
      "https://sector-a.example"
    tenant.clients.push({
      id: "rp-2",
      name: "Test RP 2",
      type: "public",
      redirectUris: ["https://app2.example/callback"],
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["openid"],
      pkceRequired: true,
      sectorIdentifier: "https://sector-b.example",
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
      success: async () =>
        ({
          type: "user",
          properties: { userId: "stable-user-2" },
        }) as never,
    })

    const subFor = async (clientId: string, redirectUri: string) => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      const challenge = await s256Challenge(verifier)
      const authorizeRes = await idp.handle(
        new Request(
          authorizeUrl(issuerUrl, {
            response_type: "code",
            client_id: clientId,
            redirect_uri: redirectUri,
            scope: "openid",
            state: "s",
            code_challenge: challenge,
            code_challenge_method: "S256",
          }),
        ),
      )
      const cb = await driveCallback(idp, authorizeRes.headers.get("location")!)
      const code = new URL(cb.headers.get("location")!).searchParams.get(
        "code",
      )!
      const tokens = (await idp
        .handle(
          tokenRequest(issuerUrl, {
            grant_type: "authorization_code",
            code,
            client_id: clientId,
            redirect_uri: redirectUri,
            code_verifier: verifier,
          }),
        )
        .then((r) => r.json())) as TokenResponse
      const keys = unwrapKeys(await keyStore.signingKeys())
      const claims = await verifyIdToken(requireIdToken(tokens), keys)
      return claims.sub
    }

    const subA = await subFor("rp-1", "https://app.example/callback")
    const subB = await subFor("rp-2", "https://app2.example/callback")
    expect(subA).not.toBe(subB)
  })

  // ─── case POLISH-PAIRWISE-3 ── discovery advertises both subject types ──
  test("POLISH-PAIRWISE-3. Discovery advertises subject_types_supported = ['public', 'pairwise']", async () => {
    const h = await buildConfidentialHarness()
    const doc = (await h.idp
      .handle(new Request(h.issuerUrl + "/.well-known/openid-configuration"))
      .then((r) => r.json())) as Record<string, unknown>
    expect(doc.subject_types_supported).toEqual(["public", "pairwise"])
  })
})

describe("RFC 7591 — Dynamic Client Registration", () => {
  async function buildRegisterHarness(opts: {
    withHook?: boolean
  } = {}) {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const issuerUrl = "https://idp.example"
    const auditLog = new MemoryAuditLog()
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({})
    const tokenStore = new MemoryTokenStore({ keyStore })
    const sessionStore = new MemorySessionStore({})

    const persisted: Array<{ id: string }> = []

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
      ...(opts.withHook
        ? {
            registerClient: async (input) => {
              const id = `dcr-${persisted.length + 1}`
              const secret = "minted-secret"
              const secretHash = await hashClientSecret(secret)
              persisted.push({ id })
              const isPublic =
                input.request.token_endpoint_auth_method === "none"
              const client = isPublic
                ? ({
                    id,
                    name: input.request.client_name ?? id,
                    type: "public" as const,
                    redirectUris: input.request.redirect_uris,
                    grantTypes: ["authorization_code", "refresh_token"] as const,
                    scopes: ["openid"],
                    pkceRequired: true as const,
                  } as never)
                : ({
                    id,
                    name: input.request.client_name ?? id,
                    type: "confidential" as const,
                    secretHash,
                    redirectUris: input.request.redirect_uris,
                    grantTypes: ["authorization_code", "refresh_token"] as const,
                    scopes: ["openid"],
                    pkceRequired: true,
                  } as never)
              return ok({
                client,
                ...(isPublic ? {} : { secret }),
              })
            },
          }
        : {}),
    })
    return { idp, issuerUrl, persisted }
  }

  // ─── case POLISH-DCR-1 ── §3.2.1 happy path ──
  test("POLISH-DCR-1. POST /register with valid body → 201 + client_id + client_secret", async () => {
    const h = await buildRegisterHarness({ withHook: true })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Acme App",
          redirect_uris: ["https://acme.example/cb"],
          token_endpoint_auth_method: "client_secret_basic",
        }),
      }),
    )
    expect(res.status).toBe(201)
    const body = (await res.json()) as Record<string, unknown>
    expect(typeof body.client_id).toBe("string")
    expect(body.client_secret).toBe("minted-secret")
    expect(typeof body.client_id_issued_at).toBe("number")
    expect(body.client_secret_expires_at).toBe(0)
    expect(body.redirect_uris).toEqual(["https://acme.example/cb"])
  })

  // ─── case POLISH-DCR-2 ── public client omits client_secret ──
  test("POLISH-DCR-2. POST /register with token_endpoint_auth_method=none → response has no client_secret", async () => {
    const h = await buildRegisterHarness({ withHook: true })
    const body = (await h.idp
      .handle(
        new Request(h.issuerUrl + "/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client_name: "Acme SPA",
            redirect_uris: ["https://acme.example/cb"],
            token_endpoint_auth_method: "none",
          }),
        }),
      )
      .then((r) => r.json())) as Record<string, unknown>
    expect(body.client_id).toBeString()
    expect(body.client_secret).toBeUndefined()
  })

  // ─── case POLISH-DCR-3 ── §3.2.2 invalid redirect_uri ──
  test("POLISH-DCR-3. POST /register with invalid redirect_uri → 400 invalid_request", async () => {
    const h = await buildRegisterHarness({ withHook: true })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["not-a-url"],
        }),
      }),
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_request",
    )
  })

  // ─── case POLISH-DCR-4 ── no hook → not enabled ──
  test("POLISH-DCR-4. /register without registerClient hook → 400 invalid_request", async () => {
    const h = await buildRegisterHarness({ withHook: false })
    const res = await h.idp.handle(
      new Request(h.issuerUrl + "/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["https://acme.example/cb"],
        }),
      }),
    )
    expect(res.status).toBe(400)
    const body = (await res.json()) as {
      error: string
      error_description: string
    }
    expect(body.error).toBe("invalid_request")
    expect(body.error_description).toContain("not enabled")
  })

  // ─── case POLISH-DCR-5 ── discovery advertises registration_endpoint ──
  test("POLISH-DCR-5. Discovery advertises registration_endpoint", async () => {
    const h = await buildRegisterHarness({ withHook: true })
    const doc = (await h.idp
      .handle(new Request(h.issuerUrl + "/.well-known/openid-configuration"))
      .then((r) => r.json())) as Record<string, unknown>
    expect(doc.registration_endpoint).toBe(h.issuerUrl + "/register")
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
