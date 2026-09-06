/**
 * Tenant recovery on POST callbacks — the middleware must accept the MAC
 * state envelope from `RelayState`, not just `state`.
 *
 * `ARCHITECTURE.md` guarantees that callbacks recover `(tenantId, flowId)`
 * from the state envelope *without* consulting `resolveTenant`; the host
 * generally cannot identify a tenant from an upstream POST. SAML's
 * HTTP-POST binding carries the envelope in `RelayState`, and the tenant
 * middleware runs before the callback domain — so until 0.14.0 the
 * middleware's own extractor, which read only `state`, silently defeated
 * that guarantee for every SP-initiated SAML callback.
 *
 * `resolveTenant` here fails on `/cb/*` on purpose. Any test that let it
 * succeed would pass with the bug present, which is exactly why this went
 * unnoticed: the SAML suite drives `dispatchMethod` directly and the one
 * HTTP-level SAML test covers the IdP-initiated path, where there is no
 * envelope to recover.
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
import { authError } from "../../src/types/error"
import { asTenantId } from "../../src/types/tenant"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"
import { testSubjects } from "../helpers/subjects"

const ISSUER = "https://idp.example"

async function harness() {
  const tenant = await buildTenant({ methods: [{ id: "stub", kind: "stub" }] })
  const clock = () => Date.now()
  const keyStore = new MemoryKeyStore({ clock })

  const idp = createIdP({
    // Succeeds for the initial /authorize, fails for every callback —
    // the shape a host is in when the upstream POSTs back with nothing
    // it can key on.
    resolveTenant: async (req: Request) => {
      if (new URL(req.url).pathname.startsWith("/cb/")) {
        return {
          ok: false as const,
          error: authError.invalidRequest("host cannot resolve on callbacks"),
        }
      }
      return { ok: true as const, value: asTenantId(tenant.id) }
    },
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore, clock }),
    sessionStore: new MemorySessionStore({ clock }),
    keyStore,
    auditLog: new MemoryAuditLog(),
    issuerUrl: ISSUER,
    methods: { stub: redirectFactory({ kind: "stub" }) as never },
    subjects: testSubjects,
    success: async ({ properties }) =>
      ({ type: "user", properties: properties as object }) as never,
  })
  return { idp, tenant }
}

/** Drive /authorize and return the minted state envelope. */
async function mintState(idp: {
  handle: (r: Request) => Promise<Response>
}): Promise<string> {
  const url = new URL(`${ISSUER}/authorize`)
  for (const [k, v] of Object.entries({
    response_type: "code",
    client_id: "rp-1",
    redirect_uri: "https://app.example/callback",
    scope: "openid",
    state: "rp-csrf",
    code_challenge: await s256Challenge("v".repeat(48)),
    code_challenge_method: "S256",
  }))
    url.searchParams.set(k, v)
  const res = await idp.handle(new Request(url.toString()))
  const upstream = new URL(res.headers.get("location")!)
  return upstream.searchParams.get("state")!
}

function postCallback(field: "state" | "RelayState", value: string) {
  return new Request(`${ISSUER}/cb/stub`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ [field]: value, code: "upstream" }).toString(),
  })
}

describe("POST callback tenant recovery", () => {
  test("recovers from RelayState (SAML HTTP-POST binding)", async () => {
    const { idp } = await harness()
    const state = await mintState(idp)

    const res = await idp.handle(postCallback("RelayState", state))

    // Recovered ⇒ the flow completed and the RP gets an auth code.
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get("location")!)
    expect(back.origin + back.pathname).toBe("https://app.example/callback")
    expect(back.searchParams.get("code")).toBeTruthy()
    expect(back.searchParams.get("state")).toBe("rp-csrf")
  })

  test("recovers from state (OAuth response_mode=form_post)", async () => {
    // The path that already worked. Present so a regression in either
    // field is attributable.
    const { idp } = await harness()
    const state = await mintState(idp)

    const res = await idp.handle(postCallback("state", state))
    expect(res.status).toBe(302)
    expect(
      new URL(res.headers.get("location")!).searchParams.get("code"),
    ).toBeTruthy()
  })

  test("a garbage RelayState does not recover a tenant", async () => {
    // The MAC is the gate. An attacker-supplied RelayState must fall
    // through to resolveTenant, which fails here — never be trusted
    // because it merely occupied the right field.
    const { idp } = await harness()
    await mintState(idp)

    const res = await idp.handle(
      postCallback("RelayState", "https://evil.example/steal"),
    )
    expect(res.status).not.toBe(302)
  })

  test("the method still sees an unconsumed body", async () => {
    // The extractor clones before reading; if it consumed the stream the
    // handler would find no `code`.
    const { idp } = await harness()
    const state = await mintState(idp)
    const res = await idp.handle(postCallback("RelayState", state))
    expect(
      new URL(res.headers.get("location")!).searchParams.get("code"),
    ).toBeTruthy()
  })
})
