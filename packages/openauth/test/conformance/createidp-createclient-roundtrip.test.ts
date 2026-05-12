/**
 * `createIdP` → `createClient.verify` round-trip.
 *
 * Regression test for the public-API agreement bug: the two halves of
 * the public API must agree on the access-token shape. `createIdP`
 * nests the `SubjectClaim` under `payload.claim = { type, properties }`
 * and does not emit a `mode` field; `createClient.verify` reads from
 * the nested shape (with a fallback to the legacy top-level shape used
 * by the deprecated `issuer({...})` API).
 *
 * If a future change reverts `createClient.verify` to insist on
 * `payload.type` / `payload.properties` / `payload.mode === "access"`,
 * this test fails — exactly the symptom the bug report described.
 */
import { describe, expect, test } from "bun:test"
import { z } from "zod"

import { createClient } from "../../src/client"
import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { s256Challenge } from "../../src/domain/pkce"
import type { SubjectSchema } from "../../src/types/subject"
import { asTenantId } from "../../src/types/tenant"
import { ok } from "../../src/types/result"

import { authorizeUrl, driveCallback, tokenRequest } from "../helpers/idp"
import { redirectFactory } from "../helpers/method"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

describe("createIdP → createClient.verify round-trip", () => {
  test("access token issued by createIdP verifies via createClient.verify", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const issuerUrl = "https://idp.example"
    const configStore = new MemoryConfigStore({ seed: [tenant] })
    const keyStore = new MemoryKeyStore({ clock: () => Date.now() })
    const tokenStore = new MemoryTokenStore({
      keyStore,
      clock: () => Date.now(),
    })
    const sessionStore = new MemorySessionStore({ clock: () => Date.now() })
    const auditLog = new MemoryAuditLog()

    // ─── IdP side ───
    const idp = createIdP({
      resolveTenant: async () => ok(asTenantId(tenant.id)),
      stateKeys: buildStateKeys(),
      configStore,
      tokenStore,
      sessionStore,
      keyStore,
      auditLog,
      issuerUrl,
      methods: { stub: redirectFactory({ kind: "stub" }) as never },
      subjects: {} as never,
      // Issue a non-default subject type to make sure the round-trip
      // preserves both the type discriminator and the properties shape.
      success: async ({ providerSubject }) =>
        ({
          type: "orgMember",
          properties: { userId: providerSubject, role: "admin" },
        }) as never,
    })

    const verifier = "v".repeat(48)
    const challenge = await s256Challenge(verifier)

    const authorize = await idp.handle(
      new Request(
        authorizeUrl(issuerUrl, {
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
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const tokRes = await idp.handle(
      tokenRequest(issuerUrl, {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }),
    )
    expect(tokRes.status).toBe(200)
    const { access_token } = (await tokRes.json()) as { access_token: string }
    expect(access_token).toBeString()

    // ─── Client side ───
    // Point `createClient` at the IdP's JWKS endpoint by short-circuiting
    // `fetch` to the IdP's `handle`. The client's discovery / JWKS path is
    // `<issuer>/.well-known/openid-configuration` → `jwks_uri`.
    const clientFetch: typeof fetch = async (input, init) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url
      return idp.handle(new Request(url, init))
    }

    const subjects = {
      orgMember: z.object({
        userId: z.string(),
        role: z.string(),
      }),
    } satisfies SubjectSchema

    const client = createClient({
      clientID: "rp-1",
      issuer: issuerUrl,
      fetch: clientFetch,
    })

    const verified = await client.verify(subjects, access_token)
    if ("err" in verified) {
      throw new Error(`verify returned err: ${verified.err.constructor.name}`)
    }
    expect(verified.aud).toBe("rp-1")
    expect(verified.subject.type).toBe("orgMember")
    // The redirectFactory stub emits providerSubject "upstream-subject";
    // our success callback maps that to properties.userId.
    expect(verified.subject.properties.userId).toBe("upstream-subject")
    expect(verified.subject.properties.role).toBe("admin")
  })

  test("verify rejects when the SubjectSchema does not include the issued subject type", async () => {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const issuerUrl = "https://idp.example"
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
      issuerUrl,
      methods: { stub: redirectFactory({ kind: "stub" }) as never },
      subjects: {} as never,
      success: async () =>
        ({
          type: "orgMember",
          properties: { userId: "u-1", role: "admin" },
        }) as never,
    })

    const verifier = "v".repeat(48)
    const challenge = await s256Challenge(verifier)
    const authorize = await idp.handle(
      new Request(
        authorizeUrl(issuerUrl, {
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
    const cb = await driveCallback(idp, authorize.headers.get("location")!)
    const code = new URL(cb.headers.get("location")!).searchParams.get("code")!
    const tok = await idp.handle(
      tokenRequest(issuerUrl, {
        grant_type: "authorization_code",
        code,
        client_id: "rp-1",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }),
    )
    const { access_token } = (await tok.json()) as { access_token: string }

    const clientFetch: typeof fetch = async (input, init) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url
      return idp.handle(new Request(url, init))
    }

    const client = createClient({
      clientID: "rp-1",
      issuer: issuerUrl,
      fetch: clientFetch,
    })

    // Schema declares a different subject type — verify must surface
    // InvalidSubjectError, not crash on a missing schema entry.
    const subjects = {
      user: z.object({ userId: z.string(), email: z.string().email() }),
    } satisfies SubjectSchema

    const verified = await client.verify(subjects as never, access_token)
    expect("err" in verified).toBe(true)
    if ("err" in verified) {
      expect(verified.err.constructor.name).toBe("InvalidSubjectError")
    }
  })
})
