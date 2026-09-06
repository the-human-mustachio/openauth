/**
 * H6 regression — cross-tenant introspect must collapse to {active: false}.
 *
 * Pre-fix order: verify token → load TOKEN's tenant → lookup presenter
 * in that tenant. If the presenter wasn't registered in the token's
 * tenant, the response was `invalid_client` — distinguishable from the
 * `{active: false}` returned for a token the presenter merely doesn't
 * own. A presenter authenticated in tenant X could probe whether its
 * client_id existed in tenant Y by watching the response shape.
 *
 * Post-fix: authenticate against the PRESENTER's tenant first; once
 * authenticated, the presenter's tenant ≠ the token's tenant collapses
 * to `{active: false}` exactly the same way other inactive-or-foreign
 * paths do.
 */
import { describe, expect, test } from "bun:test"

import { MemoryConfigStore, MemoryKeyStore } from "../../src/adapters/memory"
import { introspect } from "../../src/domain/introspect"
import { signAccessToken } from "../../src/domain/jwt"
import { hashClientSecret } from "../../src/domain/token"
import type { AccessTokenClaims } from "../../src/types/token"
import {
  asTenantId,
  type TenantConfig,
  type TenantId,
} from "../../src/types/tenant"

async function buildFixture() {
  const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
  const tenantA: TenantConfig = {
    id: asTenantId("tenant-a"),
    displayName: "A",
    clients: [
      {
        id: "rp-a",
        name: "A's RP",
        type: "confidential",
        secretHash: await hashClientSecret("secret-a"),
        redirectUris: ["https://a.example/cb"],
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["openid"],
        pkceRequired: true,
      },
    ],
    methods: [
      { id: "stub", kind: "stub", type: "custom", enabled: true, config: {} },
    ],
  }
  const tenantB: TenantConfig = {
    id: asTenantId("tenant-b"),
    displayName: "B",
    clients: [
      {
        id: "rp-b",
        name: "B's RP",
        type: "confidential",
        secretHash: await hashClientSecret("secret-b"),
        redirectUris: ["https://b.example/cb"],
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["openid"],
        pkceRequired: true,
      },
    ],
    methods: [
      { id: "stub", kind: "stub", type: "custom", enabled: true, config: {} },
    ],
  }
  const configStore = new MemoryConfigStore({ seed: [tenantA, tenantB] })

  // Mint a JWT belonging to tenant A / rp-a.
  const signingRes = await keyStore.currentSigningKey()
  if (!signingRes.ok) throw new Error("no signing key")
  const signing = signingRes.value
  const claims: AccessTokenClaims = {
    iss: "https://idp.example",
    sub: "user-1",
    aud: "rp-a",
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000),
    tid: tenantA.id as TenantId,
    mid: "stub",
    mkind: "stub",
    scope: "openid",
    claim: { type: "user", properties: { userId: "u1" } } as never,
  }
  const accessTokenA = await signAccessToken(
    claims,
    signing.privateKeyRef as Parameters<typeof signAccessToken>[1],
    signing.alg,
    signing.kid,
  )

  return { keyStore, configStore, tenantA, tenantB, accessTokenA }
}

describe("introspect: cross-tenant presenter (H6)", () => {
  test("rp-b authenticating against tenant-b cannot probe tenant-a's tokens", async () => {
    const f = await buildFixture()
    const res = await introspect(
      {
        token: f.accessTokenA,
        clientId: "rp-b",
        clientSecret: "secret-b",
        presenterTenantId: f.tenantB.id,
      },
      {
        keyStore: f.keyStore,
        configStore: f.configStore,
        issuerUrl: "https://idp.example",
      },
    )
    expect(res.ok).toBe(true)
    if (res.ok) expect(res.value.active).toBe(false)
  })

  test("rp-b with wrong secret → invalid_client (auth fails before any token signal)", async () => {
    const f = await buildFixture()
    const res = await introspect(
      {
        token: f.accessTokenA,
        clientId: "rp-b",
        clientSecret: "wrong-secret",
        presenterTenantId: f.tenantB.id,
      },
      {
        keyStore: f.keyStore,
        configStore: f.configStore,
        issuerUrl: "https://idp.example",
      },
    )
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error.code).toBe("invalid_client")
  })

  test("rp-a authenticating against its own tenant sees the token", async () => {
    const f = await buildFixture()
    const res = await introspect(
      {
        token: f.accessTokenA,
        clientId: "rp-a",
        clientSecret: "secret-a",
        presenterTenantId: f.tenantA.id,
      },
      {
        keyStore: f.keyStore,
        configStore: f.configStore,
        issuerUrl: "https://idp.example",
      },
    )
    expect(res.ok).toBe(true)
    if (res.ok && res.value.active) {
      expect(res.value.tid).toBe(f.tenantA.id)
      expect(res.value.aud).toBe("rp-a")
    } else {
      throw new Error("expected active=true for the owning client")
    }
  })
})
