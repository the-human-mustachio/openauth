/**
 * `codeMethod` end-to-end test. The deterministic `generateCode` override
 * lets the test know what code was minted; the `sendCode` hook captures
 * deliveries.
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
import { codeMethod } from "../../src/methods/code"
import { asTenantId } from "../../src/types/tenant"
import { ok } from "../../src/types/result"

import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"
import { authorizeUrl, tokenRequest } from "../helpers/idp"

describe("codeMethod", () => {
  test("end-to-end: authorize → send → verify → token", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "code", kind: "code" }],
    })
    tenant.methods[0]!.type = "code"

    const deliveries: Array<{ destination: string; code: string }> = []
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({
      keyStore,
      clock: () => Date.now(),
    })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const auditLog = new MemoryAuditLog()

    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog,
      issuerUrl: "https://idp.example",
      methods: {
        code: codeMethod({
          sendCode: async ({ destination, code }) => {
            deliveries.push({ destination, code })
          },
          generateCode: () => "424242",
        }) as never,
      },
      subjects: {} as never,
      success: async ({ properties }) =>
        ({ type: "user", properties: properties as object }) as never,
    })

    const verifier = "v".repeat(48)
    const challenge = await s256Challenge(verifier)

    // 1. /authorize → request form, flow cookie.
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
    expect(authorize.status).toBe(200)
    const flowId = authorize.headers
      .getSetCookie()
      .find((c) => c.startsWith("idp.flow="))!
      .split(";")[0]!
      .split("=")[1]!

    // 2. POST /m/code/send → mint, deliver, render verify form.
    const send = await idp.handle(
      new Request("https://idp.example/m/code/send", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: `idp.flow=${flowId}`,
        },
        body: new URLSearchParams({
          destination: "ada@example.com",
        }).toString(),
      }),
    )
    expect(send.status).toBe(200)
    expect(deliveries).toEqual([
      { destination: "ada@example.com", code: "424242" },
    ])

    // 3. POST /m/code/verify with the WRONG code first → form with error.
    const wrong = await idp.handle(
      new Request("https://idp.example/m/code/verify", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: `idp.flow=${flowId}`,
        },
        body: new URLSearchParams({ code: "000000" }).toString(),
      }),
    )
    expect(wrong.status).toBe(400)

    // 4. Correct code → 302 to RP with code.
    const verify = await idp.handle(
      new Request("https://idp.example/m/code/verify", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: `idp.flow=${flowId}`,
        },
        body: new URLSearchParams({ code: "424242" }).toString(),
      }),
    )
    expect(verify.status).toBe(302)
    const code = new URL(verify.headers.get("location")!).searchParams.get(
      "code",
    )!

    // 5. /token → tokens.
    const tokenRes = await idp.handle(
      tokenRequest("https://idp.example", {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }),
    )
    expect(tokenRes.status).toBe(200)
    const body = await tokenRes.json()
    expect(body.access_token).toBeString()
  })
})
