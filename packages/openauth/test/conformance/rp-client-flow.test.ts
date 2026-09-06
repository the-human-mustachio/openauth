/**
 * The relying-party client flow, executed end to end.
 *
 * `createClient.authorize()` → callback → `exchange()` → `verify()`, for
 * a public and a confidential client, against a real `createIdP`.
 *
 * None of `authorize`, `exchange` or `refresh` had a single test before
 * 0.14.0 — only `verify` did — which is how the documented flow shipped
 * unable to complete against either kind of client. `authorize()` sent no
 * PKCE unless asked, and the IdP requires it for public clients;
 * `exchange()` and `refresh()` presented no client credentials at all, so
 * confidential clients were rejected too. This file exists so that any
 * regression in the flow the README shows fails here first.
 */
import { describe, expect, test } from "bun:test"
import { z } from "zod"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createClient } from "../../src/client"
import { createIdP } from "../../src/index"
import { ok } from "../../src/types/result"
import type { SubjectSchema } from "../../src/types/subject"
import { asTenantId } from "../../src/types/tenant"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

const ISSUER = "https://idp.example"
const REDIRECT = "https://app.example/callback"
const SECRET = "confidential-secret"

const subjects = {
  user: z.object({ userId: z.string() }),
} satisfies SubjectSchema

async function buildIdP(clientType: "public" | "confidential") {
  const tenant = await buildTenant({
    clientType,
    ...(clientType === "confidential" ? { clientSecretPlain: SECRET } : {}),
    methods: [{ id: "stub", kind: "stub" }],
  })
  const clock = () => Date.now()
  const keyStore = new MemoryKeyStore({ clock })
  const idp = createIdP({
    resolveTenant: async () => ok(asTenantId(tenant.id)),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore, clock }),
    sessionStore: new MemorySessionStore({ clock }),
    keyStore,
    auditLog: new MemoryAuditLog(),
    issuerUrl: ISSUER,
    methods: { stub: redirectFactory({ kind: "stub" }) as never },
    subjects,
    success: async ({ providerSubject }) =>
      ({ type: "user", properties: { userId: providerSubject } }) as never,
  })
  // Route the client's HTTP calls straight into the IdP.
  const clientFetch: typeof fetch = async (i, init) => {
    const url =
      typeof i === "string" ? i : i instanceof URL ? i.toString() : i.url
    return idp.handle(new Request(url, init))
  }
  return { idp, clientFetch }
}

/** Walk the upstream redirect the way a browser would, back to /cb. */
async function followUpstream(
  idp: { handle: (r: Request) => Promise<Response> },
  authorizeUrl: string,
): Promise<string> {
  const toUpstream = await idp.handle(new Request(authorizeUrl))
  const upstream = new URL(toUpstream.headers.get("location")!)
  const cb = await idp.handle(
    new Request(
      `${upstream.searchParams.get("redirect_uri")}?state=${encodeURIComponent(
        upstream.searchParams.get("state")!,
      )}&code=upstream`,
    ),
  )
  return new URL(cb.headers.get("location")!).searchParams.get("code")!
}

describe("public client — the SPA / mobile flow", () => {
  test("authorize → exchange → verify completes", async () => {
    const { idp, clientFetch } = await buildIdP("public")
    const client = createClient({
      clientID: "rp-1",
      issuer: ISSUER,
      fetch: clientFetch,
    })

    const { challenge, url } = await client.authorize(REDIRECT)
    // PKCE is unconditional now: the IdP rejects a public client without
    // it, which is precisely what used to make this flow impossible.
    expect(new URL(url).searchParams.get("code_challenge")).toBeTruthy()
    expect(new URL(url).searchParams.get("code_challenge_method")).toBe("S256")
    expect(challenge.verifier).toBeTruthy()

    const code = await followUpstream(idp, url)
    const exchanged = await client.exchange(code, REDIRECT, challenge.verifier)
    expect(exchanged.err).toBe(false)
    if (exchanged.err) return

    const verified = await client.verify(subjects, exchanged.tokens.access)
    expect(verified.err).toBe(false)
    if (verified.err) return
    expect(verified.subject.properties.userId).toBe("upstream-subject")
  })

  test("exchanging without the verifier is rejected", async () => {
    const { idp, clientFetch } = await buildIdP("public")
    const client = createClient({
      clientID: "rp-1",
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const { url } = await client.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await client.exchange(code, REDIRECT)
    expect(exchanged.err).toBeTruthy()
  })
})

describe("confidential client — the server-side flow", () => {
  test("authorize → exchange → verify completes with a secret", async () => {
    const { idp, clientFetch } = await buildIdP("confidential")
    const client = createClient({
      clientID: "rp-1",
      clientSecret: SECRET,
      issuer: ISSUER,
      fetch: clientFetch,
    })

    const { challenge, url } = await client.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await client.exchange(code, REDIRECT, challenge.verifier)
    expect(exchanged.err).toBe(false)
    if (exchanged.err) return

    const verified = await client.verify(subjects, exchanged.tokens.access)
    expect(verified.err).toBe(false)
  })

  test("client_secret_post is accepted as well as Basic", async () => {
    const { idp, clientFetch } = await buildIdP("confidential")
    const client = createClient({
      clientID: "rp-1",
      clientSecret: SECRET,
      tokenEndpointAuthMethod: "client_secret_post",
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const { challenge, url } = await client.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await client.exchange(code, REDIRECT, challenge.verifier)
    expect(exchanged.err).toBe(false)
  })

  test("omitting the secret fails — the token endpoint cannot authenticate", async () => {
    const { idp, clientFetch } = await buildIdP("confidential")
    const client = createClient({
      clientID: "rp-1",
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const { challenge, url } = await client.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await client.exchange(code, REDIRECT, challenge.verifier)
    expect(exchanged.err).toBeTruthy()
  })

  test("refresh presents client credentials", async () => {
    // `refresh()` sent neither client_id nor a secret, so the IdP refused
    // it for confidential clients under RFC 6749 §6.
    const { idp, clientFetch } = await buildIdP("confidential")
    const client = createClient({
      clientID: "rp-1",
      clientSecret: SECRET,
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const { challenge, url } = await client.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await client.exchange(code, REDIRECT, challenge.verifier)
    if (exchanged.err) throw new Error("exchange failed")

    const refreshed = await client.refresh(exchanged.tokens.refresh)
    expect(refreshed.err).toBe(false)
    if (refreshed.err) return
    expect(refreshed.tokens?.access).toBeTruthy()
  })
})

describe("verify enforces the token audience", () => {
  test("a token minted for another client is rejected", async () => {
    // Cross-client confusion: before 0.14.0 `verify` passed only `issuer`
    // to jwtVerify, so every RP sharing an issuer accepted every other
    // RP's tokens.
    const { idp, clientFetch } = await buildIdP("public")
    const rp1 = createClient({
      clientID: "rp-1",
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const { challenge, url } = await rp1.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await rp1.exchange(code, REDIRECT, challenge.verifier)
    if (exchanged.err) throw new Error("exchange failed")

    const someoneElse = createClient({
      clientID: "rp-2",
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const verified = await someoneElse.verify(subjects, exchanged.tokens.access)
    expect(verified.err).toBeTruthy()
  })

  test("the issuing client still accepts its own token", async () => {
    const { idp, clientFetch } = await buildIdP("public")
    const rp1 = createClient({
      clientID: "rp-1",
      issuer: ISSUER,
      fetch: clientFetch,
    })
    const { challenge, url } = await rp1.authorize(REDIRECT)
    const code = await followUpstream(idp, url)
    const exchanged = await rp1.exchange(code, REDIRECT, challenge.verifier)
    if (exchanged.err) throw new Error("exchange failed")
    const verified = await rp1.verify(subjects, exchanged.tokens.access)
    expect(verified.err).toBe(false)
  })
})
