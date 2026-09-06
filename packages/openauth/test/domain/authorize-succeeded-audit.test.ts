/**
 * `authorize_succeeded` completes the audit triad.
 *
 * `AuditLog` declared `authorize_started`, `authorize_succeeded` and
 * `authorize_failed`. Only the first and last were ever emitted, so an
 * operator could see attempts and failures but never successes — while
 * `IdPOptions.hooks.onSuccess/onFailure` sat alongside as a second,
 * entirely inert observation surface. 0.14.0 removes the hooks and emits
 * the event that already existed: one mechanism, complete.
 *
 * Covered here for each path that mints an authorization code, since they
 * are separate functions that had each to be fixed individually.
 */
import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { s256Challenge } from "../../src/domain/pkce"
import { createIdP } from "../../src/index"
import { codeMethod } from "../../src/methods/code"
import { asTenantId } from "../../src/types/tenant"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { testSubjects } from "../helpers/subjects"
import { buildTenant } from "../helpers/tenant"

const ISSUER = "https://idp.example"

async function build(kind: "stub" | "code") {
  const tenant = await buildTenant({ methods: [{ id: kind, kind }] })
  tenant.methods[0]!.type = kind === "code" ? "code" : "custom"
  const clock = () => Date.now()
  const keyStore = new MemoryKeyStore({ clock })
  const auditLog = new MemoryAuditLog()
  const idp = createIdP({
    resolveTenant: async () => ({ ok: true, value: asTenantId(tenant.id) }),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore, clock }),
    sessionStore: new MemorySessionStore({ clock }),
    keyStore,
    auditLog,
    issuerUrl: ISSUER,
    methods: {
      [kind]:
        kind === "code"
          ? (codeMethod({
              sendCode: async () => {},
              generateCode: () => "424242",
            }) as never)
          : (redirectFactory({ kind: "stub" }) as never),
    } as never,
    subjects: testSubjects,
    success: async ({ properties }) =>
      ({ type: "user", properties: properties as object }) as never,
  })
  return { idp, auditLog }
}

async function authorize(idp: { handle: (r: Request) => Promise<Response> }) {
  const url = new URL(`${ISSUER}/authorize`)
  for (const [k, v] of Object.entries({
    response_type: "code",
    client_id: "rp-1",
    redirect_uri: "https://app.example/callback",
    scope: "openid",
    state: "s",
    code_challenge: await s256Challenge("v".repeat(48)),
    code_challenge_method: "S256",
  }))
    url.searchParams.set(k, v)
  return idp.handle(new Request(url.toString()))
}

describe("authorize_succeeded", () => {
  test("fires on the upstream-callback path, naming the provider subject", async () => {
    const { idp, auditLog } = await build("stub")
    const res = await authorize(idp)
    const upstream = new URL(res.headers.get("location")!)
    const state = upstream.searchParams.get("state")!

    expect(auditLog.byKind("authorize_succeeded").length).toBe(0)

    await idp.handle(
      new Request(
        `${ISSUER}/cb/stub?state=${encodeURIComponent(state)}&code=upstream`,
      ),
    )

    const events = auditLog.byKind("authorize_succeeded")
    expect(events.length).toBe(1)
    const e = events[0] as {
      clientId: string
      methodKind: string
      flowId: string
      providerSubject: string
    }
    expect(e.clientId).toBe("rp-1")
    expect(e.methodKind).toBe("stub")
    expect(e.flowId).toBeTruthy()
    // The upstream id, not the OIDC subject: `success()` has not run yet.
    expect(e.providerSubject).toBe("upstream-subject")
  })

  test("fires on the credential-POST path", async () => {
    // A separate function from the callback path, fixed separately.
    const { idp, auditLog } = await build("code")
    const first = await authorize(idp)
    const cookie = first.headers.get("set-cookie")!.split(";")[0]!

    const send = async (path: string, body: Record<string, string>) =>
      idp.handle(
        new Request(`${ISSUER}${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            cookie,
          },
          body: new URLSearchParams(body).toString(),
        }),
      )

    await send("/m/code/send", { destination: "ada@example.com" })
    expect(auditLog.byKind("authorize_succeeded").length).toBe(0)

    await send("/m/code/verify", { code: "424242" })

    const events = auditLog.byKind("authorize_succeeded")
    expect(events.length).toBe(1)
    expect((events[0] as { providerSubject: string }).providerSubject).toBe(
      "ada@example.com",
    )
  })

  test("does not fire when authorization fails", async () => {
    const { idp, auditLog } = await build("code")
    const first = await authorize(idp)
    const cookie = first.headers.get("set-cookie")!.split(";")[0]!

    await idp.handle(
      new Request(`${ISSUER}/m/code/send`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie,
        },
        body: new URLSearchParams({
          destination: "ada@example.com",
        }).toString(),
      }),
    )
    await idp.handle(
      new Request(`${ISSUER}/m/code/verify`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie,
        },
        body: new URLSearchParams({ code: "000000" }).toString(),
      }),
    )

    expect(auditLog.byKind("authorize_succeeded").length).toBe(0)
  })
})
