/**
 * End-to-end test of the Phase 2 domain functions over memory adapters.
 *
 * Demonstrates the Phase 2 acceptance criterion from
 * `docs/plans/claude/idp-rebuild-plan.md`:
 *
 *     "A test demonstrates the full authorize → token → refresh → revoke
 *      loop with memory adapters."
 */
import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { startAuthorize } from "../../src/domain/authorize"
import { handleCallback } from "../../src/domain/callback"
import { MethodCache } from "../../src/domain/method-cache"
import { introspect } from "../../src/domain/introspect"
import { refreshTokens } from "../../src/domain/refresh"
import { revokeToken } from "../../src/domain/revoke"
import { exchangeCode } from "../../src/domain/token"
import { s256Challenge } from "../../src/domain/pkce"
import type { AuthorizationRequest } from "../../src/types/authorization"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant, tenantContextFor } from "../helpers/tenant"

describe("end-to-end: authorize → callback → token → refresh → revoke", () => {
  test("the full loop succeeds against memory adapters", async () => {
    // ─── 1. Setup ───
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const issuerUrl = "https://idp.example"
    let now = Date.now()
    const clock = () => now

    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const sessionStore = new MemorySessionStore({ clock })
    const keyStore = new MemoryKeyStore({ clock })
    const tokenStore = new MemoryTokenStore({ keyStore, clock })
    const auditLog = new MemoryAuditLog()
    const methodCache = new MethodCache({
      factories: { stub: redirectFactory({ kind: "stub" }) as never },
      auditLog,
      now: clock,
    })
    const stateKeys = buildStateKeys()

    const verifier =
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_extended_to_43"
    const challenge = await s256Challenge(verifier)

    const authRequest: AuthorizationRequest = {
      tenantId: tenant.id,
      clientId: "rp-1",
      redirectUri: "https://app.example/callback",
      responseType: "code",
      scopes: ["openid"],
      state: "rp-csrf",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    }

    // ─── 2. /authorize → upstream redirect ───
    const authorize = await startAuthorize(
      {
        request: authRequest,
        rawRequest: new Request(`${issuerUrl}/authorize`),
        tenant: tenantContextFor(tenant),
        cookies: new Map(),
      },
      {
        sessionStore,
        tokenStore,
        keyStore,
        auditLog,
        methodCache,
        stateKeys,
        issuerUrl,
        clock,
      },
    )
    expect(authorize.ok).toBe(true)
    if (!authorize.ok || authorize.value.kind !== "challenge") {
      throw new Error("expected upstream redirect challenge")
    }
    const upstreamLoc = authorize.value.response.headers.get("location")!
    const stateParam = new URL(upstreamLoc).searchParams.get("state")!

    // ─── 3. Upstream callback → /token (auth code minted) ───
    const callbackResult = await handleCallback(
      {
        rawRequest: new Request(
          `${issuerUrl}/cb/stub?state=${encodeURIComponent(stateParam)}&code=upstream`,
        ),
        cookies: new Map(),
      },
      {
        configStore,
        sessionStore,
        tokenStore,
        keyStore,
        auditLog,
        methodCache,
        stateKeys,
        clock,
      },
    )
    expect(callbackResult.ok).toBe(true)
    if (!callbackResult.ok || callbackResult.value.kind !== "issue-code") {
      throw new Error("expected issue-code")
    }
    const code = callbackResult.value.code
    expect(callbackResult.value.appRedirectUri).toBe(
      "https://app.example/callback",
    )
    expect(callbackResult.value.appState).toBe("rp-csrf")

    // ─── 4. /token (authorization_code grant) ───
    const tokenRes = await exchangeCode(
      {
        grantType: "authorization_code",
        code,
        clientId: "rp-1",
        redirectUri: "https://app.example/callback",
        codeVerifier: verifier,
      },
      {
        configStore,
        tokenStore,
        keyStore,
        auditLog,
        success: async ({ providerSubject, properties }) =>
          ({
            type: "user",
            properties: { userId: providerSubject, ...(properties as object) },
          }) as never,
        issuerUrl,
        clock,
      },
    )
    expect(tokenRes.ok).toBe(true)
    if (!tokenRes.ok) throw new Error("token exchange failed")
    const access1 = tokenRes.value.access_token
    const refresh1 = tokenRes.value.refresh_token!
    expect(access1.split(".").length).toBe(3) // JWT shape

    // ─── 5. introspect the access token ───
    const intr = await introspect(
      { token: access1, clientId: "rp-1", presenterTenantId: tenant.id },
      { keyStore, configStore, issuerUrl },
    )
    expect(intr.ok).toBe(true)
    if (intr.ok && intr.value.active) {
      expect(intr.value.tid).toBe(tenant.id)
      expect(intr.value.mkind).toBe("stub")
      expect(intr.value.scope).toBe("openid")
    } else {
      throw new Error("introspect: expected active token")
    }

    // ─── 6. /token (refresh_token grant) — rotation ───
    now += 1000
    const refreshed = await refreshTokens(
      { grantType: "refresh_token", refreshToken: refresh1 },
      {
        configStore,
        tokenStore,
        keyStore,
        auditLog,
        issuerUrl,
        clock,
      },
    )
    expect(refreshed.ok).toBe(true)
    if (!refreshed.ok) throw new Error("refresh failed")
    expect(refreshed.value.refresh_token).not.toBe(refresh1)
    const refresh2 = refreshed.value.refresh_token!

    // ─── 7. Reuse the old refresh token → reuse detection ───
    now += 1000
    const reused = await refreshTokens(
      { grantType: "refresh_token", refreshToken: refresh1 },
      {
        configStore,
        tokenStore,
        keyStore,
        auditLog,
        issuerUrl,
        clock,
      },
    )
    expect(reused.ok).toBe(false)
    const reuseEvents = auditLog.byKind("refresh_reuse_detected")
    expect(reuseEvents.length).toBe(1)
    // H9: audit event must carry the peeked payload's branded tenantId /
    // clientId — never the regex's "unknown" sentinel that would blow up
    // a NOT NULL / FK column at the AuditLog adapter.
    const reuseEvent = reuseEvents[0] as {
      tenantId: string
      clientId: string
      family: string
    }
    expect(reuseEvent.tenantId).toBe(tenant.id)
    expect(reuseEvent.clientId).toBe("rp-1")
    expect(typeof reuseEvent.family).toBe("string")
    expect(reuseEvent.family.length).toBeGreaterThan(0)
    expect(reuseEvent.family).not.toBe("unknown")
    // The new refresh should also have been revoked (whole family torched).
    const tryNewAfterReuse = await refreshTokens(
      { grantType: "refresh_token", refreshToken: refresh2 },
      {
        configStore,
        tokenStore,
        keyStore,
        issuerUrl,
        clock,
      },
    )
    expect(tryNewAfterReuse.ok).toBe(false)

    // ─── 8. Revoke (no-op on already-revoked token) ───
    const revoked = await revokeToken(
      { token: refresh2, tokenTypeHint: "refresh_token" },
      { tokenStore, configStore, auditLog, clock },
    )
    expect(revoked.ok).toBe(true)

    // ─── 9. Audit trail accumulates ───
    expect(auditLog.byKind("authorize_started").length).toBe(1)
    expect(auditLog.byKind("token_issued").length).toBeGreaterThanOrEqual(1)
    expect(auditLog.byKind("token_refreshed").length).toBe(1)
  })
})
