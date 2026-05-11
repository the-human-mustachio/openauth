/**
 * `passwordMethod` end-to-end test — configure a tenant with the factory,
 * drive `/authorize` → form render → `POST /m/<id>/login` → `/token`, and
 * verify the framework issues a valid access token.
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
import { argon2idHasher } from "../../src/domain/password-hash"
import {
  passwordMethod,
  type PasswordUser,
  type PasswordUserStore,
} from "../../src/methods/password"
import { asTenantId, type TenantId } from "../../src/types/tenant"
import { ok, type Result } from "../../src/types/result"
import type { AuthError } from "../../src/types/error"

import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"
import { authorizeUrl, tokenRequest } from "../helpers/idp"

function buildMemoryUserStore(seed: PasswordUser[]): PasswordUserStore {
  const byEmail = new Map<string, PasswordUser>()
  for (const u of seed) byEmail.set(`${u.id}`, u)
  return {
    async findByEmail(email) {
      for (const u of byEmail.values()) {
        if ((u.claims as { email?: string })?.email === email) return u
      }
      return null
    },
    async create({ email, passwordHash }) {
      const id = `u-${byEmail.size + 1}`
      const user: PasswordUser = {
        id,
        passwordHash,
        claims: { email },
      }
      byEmail.set(id, user)
      return user
    },
  }
}

describe("passwordMethod", () => {
  test("end-to-end: authorize → login → token", async () => {
    // Use the lightest hasher params possible to keep the test fast.
    const hasher = argon2idHasher({ t: 1, m: 8, p: 1 })
    const pwHash = await hasher.hash("hunter2-correct-horse")
    const users = buildMemoryUserStore([
      {
        id: "u-1",
        passwordHash: pwHash,
        claims: { email: "ada@example.com" },
      },
    ])
    const tenant = await buildTenant({
      methods: [
        { id: "password", kind: "password", config: {} },
      ],
    })
    // The buildTenant helper defaults method.type to "custom" — patch.
    tenant.methods[0]!.type = "password"

    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({
      keyStore,
      clock: () => Date.now(),
    })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const auditLog = new MemoryAuditLog()

    const idp = createIdP({
      resolveTenant: async (): Promise<Result<TenantId, AuthError>> =>
        ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog,
      issuerUrl: "https://idp.example",
      methods: {
        password: passwordMethod({ users, hasher }) as never,
      },
      subjects: {} as never,
      success: async ({ providerSubject, properties }) =>
        ({
          type: "user",
          properties: {
            userId: providerSubject,
            ...(properties as object),
          },
        }) as never,
    })

    const verifier = "x".repeat(48)
    const challenge = await s256Challenge(verifier)

    // 1. /authorize → form render + idp.flow cookie.
    const authorize = await idp.handle(
      new Request(
        authorizeUrl("https://idp.example", {
          response_type: "code",
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          scope: "openid",
          state: "rp-csrf",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
      ),
    )
    expect(authorize.status).toBe(200)
    const setCookies = authorize.headers.getSetCookie()
    const flowCookie = setCookies.find((c) => c.startsWith("idp.flow="))
    expect(flowCookie).toBeDefined()
    const flowId = flowCookie!.split(";")[0]!.split("=")[1]!

    // 2. POST /m/password/login → success → 302 to RP with code.
    const login = await idp.handle(
      new Request("https://idp.example/m/password/login", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: `idp.flow=${flowId}`,
        },
        body: new URLSearchParams({
          email: "ada@example.com",
          password: "hunter2-correct-horse",
        }).toString(),
      }),
    )
    expect(login.status).toBe(302)
    const loc = new URL(login.headers.get("location")!)
    expect(loc.origin + loc.pathname).toBe("https://app.example/callback")
    expect(loc.searchParams.get("state")).toBe("rp-csrf")
    const code = loc.searchParams.get("code")!
    expect(code).toBeString()

    // 3. /token → access + refresh.
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
    expect(body.access_token.split(".").length).toBe(3)
    expect(body.refresh_token).toBeString()
  })

  test("wrong password re-renders form with error", async () => {
    const hasher = argon2idHasher({ t: 1, m: 8, p: 1 })
    const pwHash = await hasher.hash("correct-password-123")
    const users = buildMemoryUserStore([
      {
        id: "u-1",
        passwordHash: pwHash,
        claims: { email: "ada@example.com" },
      },
    ])
    const tenant = await buildTenant({
      methods: [{ id: "password", kind: "password" }],
    })
    tenant.methods[0]!.type = "password"

    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({
      keyStore,
      clock: () => Date.now(),
    })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      issuerUrl: "https://idp.example",
      methods: { password: passwordMethod({ users, hasher }) as never },
      subjects: {} as never,
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

    const login = await idp.handle(
      new Request("https://idp.example/m/password/login", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: `idp.flow=${flowId}`,
        },
        body: new URLSearchParams({
          email: "ada@example.com",
          password: "WRONG",
        }).toString(),
      }),
    )
    expect(login.status).toBe(400)
    expect(await login.text()).toContain("Invalid email or password")
  })
})
