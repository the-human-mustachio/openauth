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
