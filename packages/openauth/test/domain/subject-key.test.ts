/**
 * `subjectKey` — a stable identity seed for the derived `sub`.
 *
 * By default `sub` is a hash of the whole of `claim.properties`. That is
 * only stable if the record is, and the library actively pushes hosts to
 * put mutable data there: `customScopeClaims` publishes id_token and
 * userinfo claims from the same record (`domain/id-token.ts` — "sourced
 * from SubjectClaim.properties"). So a host exposing a role or a display
 * name, which is what the feature exists for, gets a `sub` that moves
 * whenever that value moves — contrary to OIDC Core §2, which requires it
 * never be reassigned.
 *
 * These pin the property that matters: with `subjectKey` configured, the
 * subject id survives a change to everything else in the claim, while
 * pairwise derivation is untouched.
 */
import { describe, expect, test } from "bun:test"
import { z } from "zod"

import {
  MemoryConfigStore,
  MemoryKeyStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { exchangeCode, saveEncryptedCode } from "../../src/domain/token"
import type { SubjectKey } from "../../src/types/idp"
import type { SubjectSchema } from "../../src/types/subject"
import { asTenantId, type ClientConfig } from "../../src/types/tenant"
import { buildTenant } from "../helpers/tenant"

const ISSUER = "https://idp.example"
const REDIRECT = "https://app.example/callback"

// The shape the flaw actually shows up in: a stable id sitting next to
// claims the host publishes through `customScopeClaims`.
const subjects = {
  user: z.object({
    userId: z.string(),
    role: z.string(),
    email: z.string(),
  }),
} satisfies SubjectSchema

/** Issue once and return the `sub` the library signed. */
async function subFor(opts: {
  properties: Record<string, unknown>
  subjectKey?: SubjectKey
  sectorIdentifier?: string
}): Promise<string> {
  const tenant = await buildTenant({ methods: [{ id: "stub", kind: "stub" }] })
  if (opts.sectorIdentifier) {
    ;(
      tenant.clients[0] as ClientConfig & { sectorIdentifier?: string }
    ).sectorIdentifier = opts.sectorIdentifier
  }
  const clock = () => 1_000
  const keyStore = new MemoryKeyStore({ clock })
  const tokenStore = new MemoryTokenStore({ keyStore, clock })

  await saveEncryptedCode(
    "c",
    {
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
    } as never,
    60_000,
    { keyStore, tokenStore },
  )

  const res = await exchangeCode(
    {
      grantType: "authorization_code",
      code: "c",
      clientId: "rp-1",
      redirectUri: REDIRECT,
    },
    {
      configStore: new MemoryConfigStore({ seed: [tenant] }),
      tokenStore,
      keyStore,
      subjects,
      success: async () =>
        ({ type: "user", properties: opts.properties }) as never,
      ...(opts.subjectKey ? { subjectKey: opts.subjectKey } : {}),
      issuerUrl: ISSUER,
      clock,
    },
  )
  if (!res.ok) throw new Error(`issuance failed: ${res.error.code}`)
  const [, payload] = res.value.access_token.split(".")
  return JSON.parse(atob(payload!.replace(/-/g, "+").replace(/_/g, "/"))).sub
}

const key: SubjectKey = (claim) =>
  (claim.properties as { userId: string }).userId

describe("without subjectKey, `sub` moves with any published claim", () => {
  test("changing a role reassigns the subject id", async () => {
    // The bug, stated as a test: `role` is exactly the kind of field
    // `customScopeClaims` exists to publish.
    const before = await subFor({
      properties: { userId: "u1", role: "member", email: "a@b.com" },
    })
    const after = await subFor({
      properties: { userId: "u1", role: "admin", email: "a@b.com" },
    })
    expect(after).not.toBe(before)
  })
})

describe("with subjectKey, `sub` is stable", () => {
  test("the same key survives a role change", async () => {
    const before = await subFor({
      properties: { userId: "u1", role: "member", email: "a@b.com" },
      subjectKey: key,
    })
    const after = await subFor({
      properties: { userId: "u1", role: "admin", email: "a@b.com" },
      subjectKey: key,
    })
    expect(after).toBe(before)
  })

  test("it survives an email change too", async () => {
    const before = await subFor({
      properties: { userId: "u1", role: "member", email: "old@b.com" },
      subjectKey: key,
    })
    const after = await subFor({
      properties: { userId: "u1", role: "member", email: "new@b.com" },
      subjectKey: key,
    })
    expect(after).toBe(before)
  })

  test("different keys remain different subjects", async () => {
    const a = await subFor({
      properties: { userId: "u1", role: "member", email: "a@b.com" },
      subjectKey: key,
    })
    const b = await subFor({
      properties: { userId: "u2", role: "member", email: "a@b.com" },
      subjectKey: key,
    })
    expect(a).not.toBe(b)
  })

  test("the host's raw key is not what lands in the token", async () => {
    // The key is hashed, so an internal id is not exposed to every RP.
    const sub = await subFor({
      properties: { userId: "internal-user-1", role: "m", email: "a@b.com" },
      subjectKey: key,
    })
    expect(sub).not.toContain("internal-user-1")
  })
})

describe("pairwise derivation is unaffected", () => {
  test("a sector still forks the subject id", async () => {
    // OIDC Core §8.1 must keep working: subjectKey replaces the identity
    // half of the seed, not the sector half.
    const plain = await subFor({
      properties: { userId: "u1", role: "m", email: "a@b.com" },
      subjectKey: key,
    })
    const sectored = await subFor({
      properties: { userId: "u1", role: "m", email: "a@b.com" },
      subjectKey: key,
      sectorIdentifier: "https://sector.example",
    })
    expect(sectored).not.toBe(plain)
  })

  test("the same sector and key give the same id", async () => {
    const a = await subFor({
      properties: { userId: "u1", role: "m", email: "a@b.com" },
      subjectKey: key,
      sectorIdentifier: "https://sector.example",
    })
    const b = await subFor({
      properties: { userId: "u1", role: "admin", email: "z@b.com" },
      subjectKey: key,
      sectorIdentifier: "https://sector.example",
    })
    expect(a).toBe(b)
  })
})

describe("a key that cannot identify anyone is refused", () => {
  test("an empty key fails issuance rather than collapsing subjects", async () => {
    // Hashing "" would give every subject of this type the same `sub` --
    // silent cross-user token confusion.
    await expect(
      subFor({
        properties: { userId: "u1", role: "m", email: "a@b.com" },
        subjectKey: () => "",
      }),
    ).rejects.toThrow(/server_error/)
  })

  test("a blank key is refused too", async () => {
    await expect(
      subFor({
        properties: { userId: "u1", role: "m", email: "a@b.com" },
        subjectKey: () => "   ",
      }),
    ).rejects.toThrow(/server_error/)
  })

  test("a throwing hook fails issuance", async () => {
    await expect(
      subFor({
        properties: { userId: "u1", role: "m", email: "a@b.com" },
        subjectKey: () => {
          throw new Error("no id yet")
        },
      }),
    ).rejects.toThrow(/server_error/)
  })
})
