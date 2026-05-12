/**
 * RFC 8693 Token Exchange conformance.
 *
 * Covers the eight cases laid out in the spec:
 *   1. Happy path — subject_token + accepted audience → fresh tokens at the new tenant.
 *   2. Subject token expired                          → invalid_grant.
 *   3. Subject token un-verifiable (bad signature)    → invalid_grant.
 *   4. Host's exchangeAudience returns AuthError      → propagates (invalid_target).
 *   5. exchangeAudience not configured                → unsupported_grant_type.
 *   6. Confidential client without client_secret      → invalid_client.
 *   7. Public client presenting client_secret         → invalid_client.
 *   8. actor_token present                            → invalid_request.
 */
import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { s256Challenge } from "../../src/domain/pkce"
import { authError } from "../../src/types/error"
import type { ExchangeAudience } from "../../src/types/idp"
import { ok } from "../../src/types/result"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"

import { authorizeUrl, driveCallback, tokenRequest } from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

type Harness = Awaited<ReturnType<typeof buildExchangeHarness>>

async function buildExchangeHarness(opts: {
  exchangeAudience?: ExchangeAudience
  /** Configure the source tenant as confidential. Defaults to public. */
  confidential?: boolean
  /** Skip registering the calling client in the target tenant — exercises invalid_target. */
  omitClientInTarget?: boolean
}) {
  const issuerUrl = "https://idp.example"
  const sourceTenant = await buildTenant({
    id: "from-tenant",
    methods: [{ id: "stub", kind: "stub" }],
    scopes: ["read", "write"],
    ...(opts.confidential
      ? { clientType: "confidential", clientSecretPlain: "from-secret" }
      : {}),
  })
  // Build the target tenant — same client id (so the issued token's
  // `aud` resolves on both sides) unless the test asks us to omit it.
  const targetTenant: TenantConfig = await buildTenant({
    id: "to-tenant",
    methods: [{ id: "stub", kind: "stub" }],
    scopes: ["read", "write"],
    ...(opts.confidential
      ? { clientType: "confidential", clientSecretPlain: "to-secret" }
      : {}),
  })
  if (opts.omitClientInTarget) {
    targetTenant.clients = []
  }

  const configStore = new MemoryConfigStore({
    seed: [sourceTenant, targetTenant],
  })
  const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
  const tokenStore = new MemoryTokenStore({ keyStore, clock: () => Date.now() })
  const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
  const auditLog = new MemoryAuditLog()

  const idp = createIdP({
    resolveTenant: async () => ok(asTenantId(sourceTenant.id)),
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
        properties: { userId: providerSubject, role: "user" },
      }) as never,
    ...(opts.exchangeAudience
      ? { exchangeAudience: opts.exchangeAudience }
      : {}),
  })

  return {
    idp,
    issuerUrl,
    auditLog,
    sourceTenant,
    targetTenant,
    keyStore,
    tokenStore,
  }
}

async function issueSubjectToken(
  h: Harness,
  opts: { confidential?: boolean } = {},
): Promise<string> {
  const verifier = "v".repeat(48)
  const challenge = await s256Challenge(verifier)
  const authorize = await h.idp.handle(
    new Request(
      authorizeUrl(h.issuerUrl, {
        response_type: "code",
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        scope: "read write",
        state: "rp-csrf",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }),
    ),
  )
  const cb = await driveCallback(h.idp, authorize.headers.get("location")!)
  const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
  const tok = await h.idp.handle(
    tokenRequest(h.issuerUrl, {
      grant_type: "authorization_code",
      code,
      client_id: "rp-1",
      redirect_uri: "https://app.example/callback",
      code_verifier: verifier,
      ...(opts.confidential ? { client_secret: "from-secret" } : {}),
    }),
  )
  const body = (await tok.json()) as { access_token: string }
  return body.access_token
}

function exchangeRequest(
  base: string,
  body: Record<string, string>,
): Request {
  return new Request(base + "/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  })
}

describe("RFC 8693 token-exchange at /token", () => {
  // ─── case 1 ───
  test("happy path: valid subject_token + accepted audience → new tokens", async () => {
    const exchangeAudience: ExchangeAudience = async (currentClaim) => ({
      type: (currentClaim as { type: string }).type as never,
      properties: {
        ...((currentClaim as { properties: object }).properties),
        // Host upgrades the role on the new tenant.
        role: "admin",
      } as never,
    })
    const h = await buildExchangeHarness({ exchangeAudience })
    const subjectToken = await issueSubjectToken(h)

    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
      }),
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.access_token).toBeString()
    expect(body.access_token.split(".").length).toBe(3)
    expect(body.refresh_token).toBeString()
    expect(body.token_type).toBe("Bearer")
    expect(body.issued_token_type).toBe(ACCESS_TOKEN_TYPE)
    // Audit event captures the cross-tenant move.
    const events = h.auditLog.byKind("token_exchanged")
    expect(events.length).toBe(1)
    expect(events[0]!.fromTenantId).toBe(h.sourceTenant.id)
    expect(events[0]!.tenantId).toBe(h.targetTenant.id)
  })

  // ─── case 2 ───
  test("subject_token un-verifiable (garbage) → invalid_grant", async () => {
    const h = await buildExchangeHarness({
      exchangeAudience: async () => ({
        type: "user" as never,
        properties: {} as never,
      }),
    })
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: "not.a.jwt",
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
      }),
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("invalid_grant")
  })

  // ─── case 3 ───
  test("subject_token signed under a foreign key → invalid_grant", async () => {
    // Two harnesses with independent KeyStores. The second never trusted
    // the first's signing keys, so its /token endpoint rejects.
    const a = await buildExchangeHarness({
      exchangeAudience: async () => ({
        type: "user" as never,
        properties: {} as never,
      }),
    })
    const b = await buildExchangeHarness({
      exchangeAudience: async () => ({
        type: "user" as never,
        properties: {} as never,
      }),
    })
    const foreignToken = await issueSubjectToken(a)
    const res = await b.idp.handle(
      exchangeRequest(b.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: foreignToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: b.targetTenant.id,
      }),
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("invalid_grant")
  })

  // ─── case 4 ───
  test("host's exchangeAudience returns AuthError → propagates (invalid_target)", async () => {
    const exchangeAudience: ExchangeAudience = async () =>
      authError.invalidTarget("subject cannot access target audience")
    const h = await buildExchangeHarness({ exchangeAudience })
    const subjectToken = await issueSubjectToken(h)
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
      }),
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("invalid_target")
  })

  // ─── case 5 ───
  test("exchangeAudience not configured → unsupported_grant_type", async () => {
    const h = await buildExchangeHarness({})
    const subjectToken = await issueSubjectToken(h)
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
      }),
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("unsupported_grant_type")
  })

  // ─── case 6 ───
  test("confidential client without client_secret → invalid_client", async () => {
    const exchangeAudience: ExchangeAudience = async (currentClaim) =>
      currentClaim
    const h = await buildExchangeHarness({
      exchangeAudience,
      confidential: true,
    })
    const subjectToken = await issueSubjectToken(h, { confidential: true })
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
        client_id: "rp-1",
        // client_secret deliberately omitted
      }),
    )
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe("invalid_client")
  })

  // ─── case 7 ───
  test("public client presenting client_secret → invalid_client", async () => {
    const exchangeAudience: ExchangeAudience = async (currentClaim) =>
      currentClaim
    const h = await buildExchangeHarness({ exchangeAudience })
    const subjectToken = await issueSubjectToken(h)
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
        client_id: "rp-1",
        client_secret: "ought-not-to-be-here",
      }),
    )
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe("invalid_client")
  })

  // ─── case 8 ───
  test("actor_token present → invalid_request (delegation not supported)", async () => {
    const exchangeAudience: ExchangeAudience = async (currentClaim) =>
      currentClaim
    const h = await buildExchangeHarness({ exchangeAudience })
    const subjectToken = await issueSubjectToken(h)
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
        actor_token: "any.actor.token",
        actor_token_type: ACCESS_TOKEN_TYPE,
      }),
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("invalid_request")
    expect(body.error_description).toContain("delegation")
  })

  // ─── bonus: invalid_target when client doesn't exist in target tenant ───
  test("client not registered in target tenant → invalid_target", async () => {
    const exchangeAudience: ExchangeAudience = async (currentClaim) =>
      currentClaim
    const h = await buildExchangeHarness({
      exchangeAudience,
      omitClientInTarget: true,
    })
    const subjectToken = await issueSubjectToken(h)
    const res = await h.idp.handle(
      exchangeRequest(h.issuerUrl, {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        audience: h.targetTenant.id,
      }),
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("invalid_target")
  })
})
