/**
 * `m2mMethod` end-to-end test via the `client_credentials` grant.
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
import { m2mMethod } from "../../src/methods/m2m"
import { MethodCache } from "../../src/domain/method-cache"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"
import { ok } from "../../src/types/result"

import { buildStateKeys } from "../helpers/state-keys"
import { tokenRequest } from "../helpers/idp"

void MethodCache

describe("m2mMethod / client_credentials grant", () => {
  test("end-to-end: confidential client → access token (no refresh)", async () => {
    const secret = "super-duper-secret-2024"
    const secretHash = await hashClientSecret(secret)
    const tenant: TenantConfig = {
      id: asTenantId("acme"),
      displayName: "Acme",
      clients: [
        {
          id: "svc-1",
          name: "Service",
          type: "confidential",
          secretHash,
          redirectUris: [],
          grantTypes: ["client_credentials"],
          scopes: ["read", "write"],
          pkceRequired: false,
        },
      ],
      methods: [
        {
          id: "m2m",
          kind: "m2m",
          type: "m2m",
          enabled: true,
          config: {},
        },
      ],
    }

    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({
      keyStore,
      clock: () => Date.now(),
    })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const auditLog = new MemoryAuditLog()

    const idp = createIdP({
      resolveTenant: async () => ok(tenant.id),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog,
      issuerUrl: "https://idp.example",
      methods: {
        m2m: m2mMethod({
          verify: async ({ clientID }) => ({
            claims: { svc: clientID, tier: "gold" },
          }),
        }) as never,
      },
      subjects: {} as never,
      success: async ({ providerSubject, properties }) =>
        ({
          type: "service",
          properties: {
            id: providerSubject,
            ...(properties as object),
          },
        }) as never,
    })

    const res = await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "client_credentials",
        client_id: "svc-1",
        client_secret: secret,
        scope: "read",
      }),
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.access_token.split(".").length).toBe(3)
    expect(body.token_type).toBe("Bearer")
    // RFC 6749 §4.4.3: client_credentials SHOULD NOT issue refresh.
    expect(body.refresh_token).toBeUndefined()
    expect(body.scope).toBe("read")
  })

  test("client_credentials does NOT save an orphaned refresh row (H11)", async () => {
    const secret = "another-skip-refresh-secret"
    const secretHash = await hashClientSecret(secret)
    const tenant: TenantConfig = {
      id: asTenantId("acme"),
      displayName: "Acme",
      clients: [
        {
          id: "svc-1",
          name: "Service",
          type: "confidential",
          secretHash,
          redirectUris: [],
          grantTypes: ["client_credentials"],
          scopes: ["read"],
          pkceRequired: false,
        },
      ],
      methods: [
        { id: "m2m", kind: "m2m", type: "m2m", enabled: true, config: {} },
      ],
    }
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const inner = new MemoryTokenStore({ keyStore, clock: () => Date.now() })
    let saveRefreshCalls = 0
    const tokenStore = {
      saveCode: inner.saveCode.bind(inner),
      consumeCode: inner.consumeCode.bind(inner),
      consumeRefresh: inner.consumeRefresh.bind(inner),
      peekRefresh: inner.peekRefresh.bind(inner),
      revokeFamily: inner.revokeFamily.bind(inner),
      revokeBySubject: inner.revokeBySubject.bind(inner),
      saveRefresh: (...args: Parameters<typeof inner.saveRefresh>) => {
        saveRefreshCalls += 1
        return inner.saveRefresh(...args)
      },
    }
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const idp = createIdP({
      resolveTenant: async () => ok(tenant.id),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      issuerUrl: "https://idp.example",
      methods: {
        m2m: m2mMethod({
          verify: async () => ({}),
        }) as never,
      },
      subjects: {} as never,
      success: async ({ providerSubject }) =>
        ({ type: "service", properties: { id: providerSubject } }) as never,
    })
    const res = await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "client_credentials",
        client_id: "svc-1",
        client_secret: secret,
        scope: "read",
      }),
    )
    expect(res.status).toBe(200)
    // The refresh token would otherwise persist for 30 days even though
    // the response drops it. Assert the store was never asked to save one.
    expect(saveRefreshCalls).toBe(0)
  })

  test("client_id is injected into the URL so a search-param resolver works (H5)", async () => {
    const secret = "lookup-from-url-secret"
    const secretHash = await hashClientSecret(secret)
    const tenant: TenantConfig = {
      id: asTenantId("acme"),
      displayName: "Acme",
      clients: [
        {
          id: "svc-1",
          name: "Service",
          type: "confidential",
          secretHash,
          redirectUris: [],
          grantTypes: ["client_credentials"],
          scopes: ["read"],
          pkceRequired: false,
        },
      ],
      methods: [
        { id: "m2m", kind: "m2m", type: "m2m", enabled: true, config: {} },
      ],
    }

    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({ keyStore, clock: () => Date.now() })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })

    // Resolver mirrors INTEGRATION.md §5.1's canonical pattern: read
    // `client_id` from the URL. Pre-fix this would have failed for m2m
    // because POST /token carries client_id in the body.
    const resolved: string[] = []
    const idp = createIdP({
      resolveTenant: async (req) => {
        const url = new URL(req.url)
        const clientId = url.searchParams.get("client_id")
        resolved.push(clientId ?? "")
        if (clientId === "svc-1") return ok(tenant.id)
        return ok(asTenantId("__missing__"))
      },
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      issuerUrl: "https://idp.example",
      methods: {
        m2m: m2mMethod({
          verify: async ({ clientID }) => ({
            claims: { svc: clientID },
          }),
        }) as never,
      },
      subjects: {} as never,
      success: async ({ providerSubject }) =>
        ({ type: "service", properties: { id: providerSubject } }) as never,
    })

    const res = await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "client_credentials",
        client_id: "svc-1",
        client_secret: secret,
        scope: "read",
      }),
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body.access_token).toBe("string")
    // Resolver actually saw client_id.
    expect(resolved).toEqual(["svc-1"])
  })

  test("rejects when client lacks client_credentials grant", async () => {
    const secret = "another-secret-2024"
    const secretHash = await hashClientSecret(secret)
    const tenant: TenantConfig = {
      id: asTenantId("acme"),
      displayName: "Acme",
      clients: [
        {
          id: "rp-1",
          name: "Web RP",
          type: "confidential",
          secretHash,
          redirectUris: ["https://app.example/callback"],
          grantTypes: ["authorization_code"], // no client_credentials
          scopes: ["openid"],
          pkceRequired: true,
        },
      ],
      methods: [
        { id: "m2m", kind: "m2m", type: "m2m", enabled: true, config: {} },
      ],
    }
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({
      keyStore,
      clock: () => Date.now(),
    })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const idp = createIdP({
      resolveTenant: async () => ok(tenant.id),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      issuerUrl: "https://idp.example",
      methods: {
        m2m: m2mMethod({ verify: async () => ({}) }) as never,
      },
      subjects: {} as never,
      success: async () => ({ type: "x", properties: {} }) as never,
    })
    const res = await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "client_credentials",
        client_id: "rp-1",
        client_secret: secret,
      }),
    )
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("unauthorized_client")
  })
})
