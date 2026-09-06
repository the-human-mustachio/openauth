/**
 * `passkeyMethod` shape tests.
 *
 * A full WebAuthn ceremony requires either a real browser or a simulated
 * authenticator. Phase 4 verifies the framework wiring — form render,
 * options minting, error paths, registration gate — and defers full-
 * ceremony coverage to the manual test cadence + the management-console
 * integration in Phase 7 (where real browsers exist).
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
import { passkeyMethod } from "../../src/methods/passkey"
import { asTenantId } from "../../src/types/tenant"
import { ok } from "../../src/types/result"

import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"
import { authorizeUrl } from "../helpers/idp"
import { testSubjects } from "../helpers/subjects"

function harness() {
  return {
    findByUsername: async (
      username: string,
    ): Promise<{
      userId: string
      credentials: Array<{
        credentialId: string
        publicKey: string
        counter: number
        userId: string
      }>
    } | null> => {
      if (username === "known") {
        return {
          userId: "u-1",
          credentials: [
            {
              credentialId: "cred-1",
              publicKey: "AAAA",
              counter: 0,
              userId: "u-1",
            },
          ],
        }
      }
      return null
    },
    findById: async () => null,
    updateCounter: async () => {},
  }
}

describe("passkeyMethod (shape)", () => {
  test("GET /authorize renders username form", async () => {
    const tenant = await buildTenant({
      methods: [
        {
          id: "passkey",
          kind: "passkey",
          config: {
            rpName: "Test",
            rpID: "idp.example",
            origins: "https://idp.example",
          },
        },
      ],
    })
    tenant.methods[0]!.type = "passkey"

    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore: new MemoryConfigStore({ seed: [tenant] }),
      tokenStore: new MemoryTokenStore({
        keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
        clock: () => Date.now(),
      }),
      sessionStore: new MemorySessionStore({ clock: () => Date.now() }),
      keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
      auditLog: new MemoryAuditLog(),
      issuerUrl: "https://idp.example",
      methods: {
        passkey: passkeyMethod({ credentials: harness() }) as never,
      },
      subjects: testSubjects,
      success: async () => ({ type: "user", properties: {} }) as never,
    })

    const challenge = await s256Challenge("v".repeat(48))
    const res = await idp.handle(
      new Request(
        authorizeUrl("https://idp.example", {
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
    expect(res.status).toBe(200)
    const body = await res.text()
    expect(body).toContain('name="username"')
    expect(body).toContain("/m/passkey/authenticate-options")
  })

  test("POST /authenticate-options for known user → challenge JSON", async () => {
    const tenant = await buildTenant({
      methods: [
        {
          id: "passkey",
          kind: "passkey",
          config: {
            rpName: "Test",
            rpID: "idp.example",
            origins: "https://idp.example",
          },
        },
      ],
    })
    tenant.methods[0]!.type = "passkey"

    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore: new MemoryConfigStore({ seed: [tenant] }),
      tokenStore: new MemoryTokenStore({
        keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
        clock: () => Date.now(),
      }),
      sessionStore: new MemorySessionStore({ clock: () => Date.now() }),
      keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
      issuerUrl: "https://idp.example",
      methods: {
        passkey: passkeyMethod({ credentials: harness() }) as never,
      },
      subjects: testSubjects,
      success: async () => ({ type: "user", properties: {} }) as never,
    })

    const challenge = await s256Challenge("v".repeat(48))
    const authorize = await idp.handle(
      new Request(
        authorizeUrl("https://idp.example", {
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
    const flowId = authorize.headers
      .getSetCookie()
      .find((c) => c.startsWith("idp.flow="))!
      .split(";")[0]!
      .split("=")[1]!

    const options = await idp.handle(
      new Request("https://idp.example/m/passkey/authenticate-options", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: `idp.flow=${flowId}`,
        },
        body: new URLSearchParams({ username: "known" }).toString(),
      }),
    )
    expect(options.status).toBe(200)
    const json = await options.json()
    expect(json.challenge).toBeString()
    expect(json.rpId).toBe("idp.example")
    expect(Array.isArray(json.allowCredentials)).toBe(true)
  })
})
