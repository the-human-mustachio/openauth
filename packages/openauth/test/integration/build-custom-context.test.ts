/**
 * H12 — `IdPOptions.buildCustomContext` is the public hook that populates
 * `TenantContext.request.custom` and survives the authorize → callback →
 * token round-trip via the FlowRecord. This test wires a hook that
 * reads `x-request-id` off each request, drives the full code-grant
 * lifecycle, and asserts the value reaches the `success` callback at
 * /token time on `SuccessMapInput.context`.
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
import { hashClientSecret } from "../../src/domain/token"
import type { SuccessMapInput } from "../../src/types/idp"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"
import { ok } from "../../src/types/result"

import { redirectFactory } from "../helpers/method"
import { authorizeUrl, driveCallback, tokenRequest } from "../helpers/idp"
import { buildStateKeys } from "../helpers/state-keys"

describe("buildCustomContext hook (H12)", () => {
  test("hook output reaches success() via SuccessMapInput.context", async () => {
    const secret = "rp-secret-h12"
    const tenant: TenantConfig = {
      id: asTenantId("acme"),
      displayName: "Acme",
      clients: [
        {
          id: "rp-1",
          name: "Web RP",
          type: "confidential",
          secretHash: await hashClientSecret(secret),
          redirectUris: ["https://app.example/callback"],
          grantTypes: ["authorization_code", "refresh_token"],
          scopes: ["openid"],
          pkceRequired: false,
        },
      ],
      methods: [
        { id: "stub", kind: "stub", type: "custom", enabled: true, config: {} },
      ],
    }
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({ keyStore, clock: () => Date.now() })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })

    const successCalls: SuccessMapInput[] = []
    const idp = createIdP({
      resolveTenant: async () => ok(tenant.id),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog: new MemoryAuditLog(),
      issuerUrl: "https://idp.example",
      buildCustomContext(req) {
        return {
          rid: req.headers.get("x-request-id") ?? "missing",
          phase: req.url.includes("/cb/") ? "callback" : "authorize",
        }
      },
      methods: {
        stub: redirectFactory({
          kind: "stub",
          providerSubject: "upstream-subj",
        }) as never,
      },
      subjects: {} as never,
      success: async (input) => {
        successCalls.push(input)
        return {
          type: "user",
          properties: { userId: input.providerSubject },
        } as never
      },
    })

    // ── /authorize → upstream redirect ──
    const authorize = await idp.handle(
      new Request(
        authorizeUrl("https://idp.example", {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "rp-csrf",
        }),
        { headers: { "x-request-id": "rid-authorize" } },
      ),
    )
    expect(authorize.status).toBe(302)

    // ── Drive upstream callback ──
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    expect(cb.status).toBe(302)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!

    // ── /token ──
    const tok = await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        client_secret: secret,
        redirect_uri: "https://app.example/callback",
      }),
    )
    expect(tok.status).toBe(200)

    // success() fired once with the FlowRecord.context blob populated at
    // /authorize time (NOT the /token call's context — the flow records
    // and re-presents the value from when the user authenticated).
    expect(successCalls.length).toBe(1)
    expect(successCalls[0]!.context).toEqual({
      rid: "rid-authorize",
      phase: "authorize",
    })
  })

  test("absent hook → SuccessMapInput.context is `{}`", async () => {
    const secret = "rp-secret-h12-noop"
    const tenant: TenantConfig = {
      id: asTenantId("acme"),
      displayName: "Acme",
      clients: [
        {
          id: "rp-1",
          name: "Web RP",
          type: "confidential",
          secretHash: await hashClientSecret(secret),
          redirectUris: ["https://app.example/callback"],
          grantTypes: ["authorization_code", "refresh_token"],
          scopes: ["openid"],
          pkceRequired: false,
        },
      ],
      methods: [
        { id: "stub", kind: "stub", type: "custom", enabled: true, config: {} },
      ],
    }
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({ keyStore, clock: () => Date.now() })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })

    const successCalls: SuccessMapInput[] = []
    const idp = createIdP({
      resolveTenant: async () => ok(tenant.id),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      issuerUrl: "https://idp.example",
      methods: {
        stub: redirectFactory({ kind: "stub" }) as never,
      },
      subjects: {} as never,
      success: async (input) => {
        successCalls.push(input)
        return { type: "user", properties: { userId: "u1" } } as never
      },
    })
    const authorize = await idp.handle(
      new Request(
        authorizeUrl("https://idp.example", {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "rp-csrf",
        }),
      ),
    )
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        client_secret: secret,
        redirect_uri: "https://app.example/callback",
      }),
    )
    expect(successCalls.length).toBe(1)
    expect(successCalls[0]!.context).toEqual({})
  })
})
