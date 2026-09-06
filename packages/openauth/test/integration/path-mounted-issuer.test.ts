/**
 * The IdP mounted under a path prefix.
 *
 * Deployment shape: a reverse proxy serves the IdP at `https://x/idp` and
 * strips `/idp` before forwarding, so the service still sees its own
 * root-relative paths (`/authorize`, `/m/*`, `/cb/*`) on the way in.
 * Requests below are therefore built *unprefixed* — that is genuinely what
 * arrives — while every URL the library hands to a browser or to an
 * upstream provider must carry the prefix, because those are resolved on
 * the public side of the proxy.
 *
 * Routing and token signing were never affected by this bug, which is why
 * discovery and `/token` pass while no login can complete. The assertions
 * that matter are on *emitted* URLs.
 *
 * Each case is run twice, root-mounted and path-mounted. The root-mounted
 * half is the regression bar: those deployments must emit byte-identical
 * URLs to before mount support existed, or every registered `redirect_uri`
 * in the wild breaks.
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
import type { AuthMethodFactory } from "../../src/types/method"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

const ORIGIN = "https://example.com"

async function buildMounted(opts: {
  issuerUrl: string
  methodKind: "code" | "stub"
}) {
  const tenant = await buildTenant({
    methods: [{ id: opts.methodKind, kind: opts.methodKind }],
  })
  tenant.methods[0]!.type = opts.methodKind === "code" ? "code" : "custom"

  const clock = () => Date.now()
  const keyStore = new MemoryKeyStore({ clock })
  const factory: AuthMethodFactory =
    opts.methodKind === "code"
      ? (codeMethod({
          sendCode: async () => {},
          generateCode: () => "424242",
        }) as never)
      : (redirectFactory({ kind: "stub" }) as never)

  const idp = createIdP({
    resolveTenant: async () => ({ ok: true, value: asTenantId(tenant.id) }),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore, clock }),
    sessionStore: new MemorySessionStore({ clock }),
    keyStore,
    auditLog: new MemoryAuditLog(),
    issuerUrl: opts.issuerUrl,
    methods: { [opts.methodKind]: factory } as never,
    subjects: {} as never,
    success: async ({ properties }) =>
      ({ type: "user", properties: properties as object }) as never,
  })
  return { idp, tenant }
}

/** Drive `/authorize` against the *proxy-stripped* origin the service sees. */
async function authorize(idp: { handle: (r: Request) => Promise<Response> }) {
  const verifier = "v".repeat(48)
  const url = new URL(`${ORIGIN}/authorize`)
  for (const [k, v] of Object.entries({
    response_type: "code",
    client_id: "rp-1",
    redirect_uri: "https://app.example/callback",
    scope: "openid",
    state: "s",
    code_challenge: await s256Challenge(verifier),
    code_challenge_method: "S256",
  }))
    url.searchParams.set(k, v)
  return idp.handle(new Request(url.toString()))
}

describe("path-mounted issuer — form actions (Family A)", () => {
  test("root-mounted emits a bare /m/ action, exactly as before", async () => {
    const { idp } = await buildMounted({
      issuerUrl: ORIGIN,
      methodKind: "code",
    })
    const html = await (await authorize(idp)).text()
    expect(html).toContain('action="/m/code/send"')
  })

  test("path-mounted emits the prefix, so the form does not 404", async () => {
    const { idp } = await buildMounted({
      issuerUrl: `${ORIGIN}/idp`,
      methodKind: "code",
    })
    const html = await (await authorize(idp)).text()
    expect(html).toContain('action="/idp/m/code/send"')
    // The un-prefixed form is what 404'd; assert it is gone, not merely
    // that the prefixed one is present.
    expect(html).not.toContain('action="/m/code/send"')
  })

  test("the prefix survives a re-rendered form after a validation error", async () => {
    // The error re-render is a separate code path from the initial render,
    // and `ctx.dispatch` is null there — the reason this needed
    // `MethodContext.issuerUrl` rather than `dispatch.issuerUrl`.
    const { idp } = await buildMounted({
      issuerUrl: `${ORIGIN}/idp`,
      methodKind: "code",
    })
    const first = await authorize(idp)
    const cookie = first.headers.get("set-cookie")!.split(";")[0]!

    const bad = await idp.handle(
      new Request(`${ORIGIN}/m/code/send`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie,
        },
        body: new URLSearchParams({ destination: "not-an-email" }).toString(),
      }),
    )
    expect(bad.status).toBe(400)
    const html = await bad.text()
    expect(html).toContain('action="/idp/m/code/send"')
  })

  test("a trailing slash on the issuer does not double up", async () => {
    const { idp } = await buildMounted({
      issuerUrl: `${ORIGIN}/idp/`,
      methodKind: "code",
    })
    const html = await (await authorize(idp)).text()
    expect(html).toContain('action="/idp/m/code/send"')
    expect(html).not.toContain("//m/code/send")
  })
})

describe("path-mounted issuer — upstream redirect_uri (Family B)", () => {
  test("root-mounted callback URL is byte-identical to before", async () => {
    const { idp } = await buildMounted({
      issuerUrl: ORIGIN,
      methodKind: "stub",
    })
    const res = await authorize(idp)
    const upstream = new URL(res.headers.get("location")!)
    expect(upstream.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/cb/stub`)
  })

  test("path-mounted callback URL carries the prefix", async () => {
    // This is the serious half: the value is registered in a third
    // party's configuration, so it cannot be corrected after the fact.
    const { idp } = await buildMounted({
      issuerUrl: `${ORIGIN}/idp`,
      methodKind: "stub",
    })
    const res = await authorize(idp)
    const upstream = new URL(res.headers.get("location")!)
    expect(upstream.searchParams.get("redirect_uri")).toBe(
      `${ORIGIN}/idp/cb/stub`,
    )
  })

  test("the inbound callback still validates against the stripped path", async () => {
    // `FlowRecord.callbackPath` must stay un-prefixed: the proxy has
    // already stripped it by the time the request reaches us. Prefixing
    // the stored path would reject every callback — trading a 404 for a
    // 400 rather than fixing anything.
    const { idp } = await buildMounted({
      issuerUrl: `${ORIGIN}/idp`,
      methodKind: "stub",
    })
    const res = await authorize(idp)
    const upstream = new URL(res.headers.get("location")!)
    const state = upstream.searchParams.get("state")!

    const cb = await idp.handle(
      new Request(
        `${ORIGIN}/cb/stub?state=${encodeURIComponent(state)}&code=upstream`,
      ),
    )
    // Success ⇒ redirect back to the RP with an authorization code.
    expect(cb.status).toBe(302)
    const back = new URL(cb.headers.get("location")!)
    expect(back.origin + back.pathname).toBe("https://app.example/callback")
    expect(back.searchParams.get("code")).toBeTruthy()
  })
})
