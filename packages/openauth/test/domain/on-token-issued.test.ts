/**
 * `onTokenIssued` — the host's only route to the derived subject id.
 *
 * `deriveSubjectId` is private, and the value appears nowhere a host can
 * read it: it is signed as `sub`, and the `token_issued` audit event
 * carries it without the claim it came from, so a host receives an
 * identifier it cannot attribute to any of its own users. Meanwhile
 * `TokenStore.revokeBySubject`, `revokeAllForSubject` and `onLogout`'s
 * `revokeSubject` all take exactly that value. Without this hook the
 * revocation primitives are uncallable, and since refresh rotation mints
 * from the claim stored on the payload and never re-consults the host, an
 * offboarded user's chain renews indefinitely.
 *
 * Two properties matter beyond "it fires":
 *
 *  - it runs **before** the refresh token is persisted, so a throwing
 *    hook leaves no chain the host has no record of;
 *  - the ids it reports are **many per principal** — pairwise clients and
 *    mutable claim properties both fork them.
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
import { s256Challenge } from "../../src/domain/pkce"
import { revokeAllForSubject } from "../../src/domain/revoke"
import { exchangeCode, saveEncryptedCode } from "../../src/domain/token"
import { createIdP } from "../../src/index"
import type { OnTokenIssued } from "../../src/types/idp"
import { ok } from "../../src/types/result"
import type { SubjectSchema } from "../../src/types/subject"
import { asTenantId, type ClientConfig } from "../../src/types/tenant"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

const ISSUER = "https://idp.example"
const REDIRECT = "https://app.example/callback"

const subjects = {
  user: z.object({ userId: z.string() }),
} satisfies SubjectSchema

type Seen = Parameters<OnTokenIssued>[0]

async function build(opts: {
  onTokenIssued?: OnTokenIssued
  sectorIdentifier?: string
}) {
  const tenant = await buildTenant({ methods: [{ id: "stub", kind: "stub" }] })
  if (opts.sectorIdentifier) {
    ;(
      tenant.clients[0] as ClientConfig & { sectorIdentifier?: string }
    ).sectorIdentifier = opts.sectorIdentifier
  }
  const clock = () => Date.now()
  const keyStore = new MemoryKeyStore({ clock })
  const tokenStore = new MemoryTokenStore({ keyStore, clock })
  const idp = createIdP({
    resolveTenant: async () => ok(asTenantId(tenant.id)),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore,
    sessionStore: new MemorySessionStore({ clock }),
    keyStore,
    auditLog: new MemoryAuditLog(),
    issuerUrl: ISSUER,
    methods: { stub: redirectFactory({ kind: "stub" }) as never },
    subjects,
    success: async ({ providerSubject }) =>
      ({ type: "user", properties: { userId: providerSubject } }) as never,
    ...(opts.onTokenIssued ? { onTokenIssued: opts.onTokenIssued } : {}),
  })
  return { idp, tokenStore, tenant, clock }
}

/** authorize → upstream → callback → /token. Returns the token response. */
async function runFlow(idp: { handle: (r: Request) => Promise<Response> }) {
  const verifier = "v".repeat(48)
  const url = new URL(`${ISSUER}/authorize`)
  for (const [k, v] of Object.entries({
    response_type: "code",
    client_id: "rp-1",
    redirect_uri: REDIRECT,
    scope: "openid",
    state: "s",
    code_challenge: await s256Challenge(verifier),
    code_challenge_method: "S256",
  }))
    url.searchParams.set(k, v)

  const toUpstream = await idp.handle(new Request(url.toString()))
  const upstream = new URL(toUpstream.headers.get("location")!)
  const cb = await idp.handle(
    new Request(
      `${upstream.searchParams.get("redirect_uri")}?state=${encodeURIComponent(
        upstream.searchParams.get("state")!,
      )}&code=upstream`,
    ),
  )
  const code = new URL(cb.headers.get("location")!).searchParams.get("code")!

  return idp.handle(
    new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }).toString(),
    }),
  )
}

function decodeSub(accessToken: string): string {
  const [, payload] = accessToken.split(".")
  return JSON.parse(atob(payload!.replace(/-/g, "+").replace(/_/g, "/"))).sub
}

describe("onTokenIssued reports the id the library signs", () => {
  test("subjectId equals the access token's `sub`", async () => {
    const seen: Seen[] = []
    const { idp } = await build({ onTokenIssued: (i) => void seen.push(i) })
    const res = await runFlow(idp)
    expect(res.status).toBe(200)
    const { access_token } = (await res.json()) as { access_token: string }

    expect(seen.length).toBe(1)
    expect(seen[0]!.subjectId).toBe(decodeSub(access_token))
    expect(seen[0]!.clientId).toBe("rp-1")
    // The claim is what makes the id attributable to a host principal.
    expect(seen[0]!.claim).toEqual({
      type: "user",
      properties: { userId: "upstream-subject" },
    })
    expect(seen[0]!.family).toBeTruthy()
  })

  test("the reported subjectId actually revokes", async () => {
    // The whole point: revokeAllForSubject takes this value.
    const seen: Seen[] = []
    const { idp, tokenStore, tenant, clock } = await build({
      onTokenIssued: (i) => void seen.push(i),
    })
    const res = await runFlow(idp)
    const { refresh_token } = (await res.json()) as { refresh_token: string }

    const revoked = await revokeAllForSubject(
      asTenantId(tenant.id),
      seen[0]!.subjectId,
      { tokenStore, clock },
    )
    expect(revoked.ok).toBe(true)

    const refreshed = await idp.handle(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token,
          client_id: "rp-1",
        }).toString(),
      }),
    )
    expect(refreshed.status).not.toBe(200)
  })

  test("fires again on refresh rotation, with the same subject id", async () => {
    const seen: Seen[] = []
    const { idp } = await build({ onTokenIssued: (i) => void seen.push(i) })
    const res = await runFlow(idp)
    const { refresh_token } = (await res.json()) as { refresh_token: string }

    await idp.handle(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token,
          client_id: "rp-1",
        }).toString(),
      }),
    )
    expect(seen.length).toBe(2)
    expect(seen[1]!.subjectId).toBe(seen[0]!.subjectId)
    // Same chain, so the family is stable across rotation -- which is
    // what makes `revokeFamily` usable from a record taken at first
    // issuance.
    expect(seen[1]!.family).toBeTruthy()
    expect(seen[1]!.family).toBe(seen[0]!.family!)
  })
})

describe("a throwing hook leaves nothing behind", () => {
  test("issuance fails and no usable refresh chain is created", async () => {
    // Ordering is the point. Recording the mapping *after* saveRefresh
    // and then aborting would leave a live chain the host never saw --
    // exactly the unrevokable token this hook exists to prevent.
    const { idp } = await build({
      onTokenIssued: () => {
        throw new Error("host DB down")
      },
    })
    const res = await runFlow(idp)
    expect(res.status).toBeGreaterThanOrEqual(400)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe("server_error")
  })

  test("the refresh token that would have been minted was never stored", async () => {
    // Asserted directly through the port rather than by peeking at
    // adapter internals: pin the token the grant would mint, let the hook
    // throw, then look for it. Present ⇒ the hook ran after saveRefresh
    // and a chain outlived the failure.
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const clock = () => 1_000
    const keyStore = new MemoryKeyStore({ clock })
    const tokenStore = new MemoryTokenStore({ keyStore, clock })
    const configStore = new MemoryConfigStore({ seed: [tenant] })

    const payload = {
      tenantId: asTenantId(tenant.id),
      clientId: "rp-1",
      appRedirectUri: REDIRECT,
      appState: null,
      scopes: ["openid"],
      methodId: "stub",
      methodKind: "stub",
      context: null,
      providerSubject: "ps-1",
      properties: {},
      authTime: 1,
      expiresAt: 60_000,
    }
    await saveEncryptedCode("c", payload as never, 60_000, {
      keyStore,
      tokenStore,
    })

    const res = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "c",
        clientId: "rp-1",
        redirectUri: REDIRECT,
      },
      {
        configStore,
        tokenStore,
        keyStore,
        subjects,
        success: async () =>
          ({ type: "user", properties: { userId: "u1" } }) as never,
        onTokenIssued: () => {
          throw new Error("host DB down")
        },
        newRefreshToken: () => "would-have-been-minted",
        issuerUrl: ISSUER,
        clock,
      },
    )
    expect(res.ok).toBe(false)

    const found = await tokenStore.peekRefresh("would-have-been-minted")
    expect(found.ok).toBe(false)
  })
})

describe("one principal, many subject ids", () => {
  test("a pairwise client yields a different id for the same person", async () => {
    // OIDC Core §8.1 -- sectorIdentifier is mixed into the derivation, so
    // a host that overwrites its mapping instead of accumulating will
    // under-revoke and never notice.
    const plain: Seen[] = []
    const { idp: a } = await build({
      onTokenIssued: (i) => void plain.push(i),
    })
    await runFlow(a)

    const pairwise: Seen[] = []
    const { idp: b } = await build({
      onTokenIssued: (i) => void pairwise.push(i),
      sectorIdentifier: "https://sector.example",
    })
    await runFlow(b)

    expect(plain[0]!.claim).toEqual(pairwise[0]!.claim)
    expect(pairwise[0]!.subjectId).not.toBe(plain[0]!.subjectId)
  })
})
