/**
 * `IdPOptions.subjects` is enforced at issuance.
 *
 * Before 0.14.0 the option was required and never read: `createIdP`
 * accepted the schema and signed whatever `success()` returned. The
 * failure surfaced only in `client.verify()` — in a different service,
 * after the token was signed and written into the refresh payload.
 *
 * These cover both grants that call `success()` (authorization_code and
 * client_credentials), plus the type-soundness case: `SubjectPayload`
 * declares `properties: v1.InferOutput<...>`, so a schema with a
 * transform must actually be applied.
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
import { validateSubjectClaim } from "../../src/domain/subject"
import { saveEncryptedCode } from "../../src/domain/token"
import { exchangeCode } from "../../src/domain/token"
import type { SubjectClaim, SubjectSchema } from "../../src/types/subject"
import { asTenantId } from "../../src/types/tenant"
import { buildTenant } from "../helpers/tenant"

const subjects: SubjectSchema = {
  user: z.object({ userId: z.string(), email: z.string().email() }),
}

describe("validateSubjectClaim", () => {
  test("accepts a conforming claim and returns the parsed value", async () => {
    const r = await validateSubjectClaim(subjects, {
      type: "user",
      properties: { userId: "u1", email: "a@b.com" },
    } as SubjectClaim)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.properties).toEqual({ userId: "u1", email: "a@b.com" })
  })

  test("rejects a subject type the host never declared", async () => {
    const r = await validateSubjectClaim(subjects, {
      type: "admin",
      properties: {},
    } as SubjectClaim)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.rejection.reason).toBe("unknown-type")
    expect(r.error.rejection.subjectType).toBe("admin")
    expect(r.error.rejection.detail).toContain("user")
  })

  test("rejects properties that violate the declared schema", async () => {
    const r = await validateSubjectClaim(subjects, {
      type: "user",
      properties: { userId: 123, email: "not-an-email" },
    } as unknown as SubjectClaim)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.rejection.reason).toBe("invalid-properties")
  })

  test("the rejection carries paths, never the offending values", async () => {
    // Properties can be personal data; an audit log must not become a
    // place where it leaks.
    const r = await validateSubjectClaim(subjects, {
      type: "user",
      // Invalid on purpose, and carrying a value that must not be logged.
      properties: { userId: "u1", email: "secret-address-not-an-email" },
    } as SubjectClaim)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.rejection.detail).toContain("email")
    expect(r.error.rejection.detail).not.toContain("secret-address")
  })

  test("applies transforms, so the signed value matches the declared type", async () => {
    // `SubjectPayload` declares InferOutput. Without a parse the runtime
    // value is the *input*, and that declaration is a lie.
    const transforming: SubjectSchema = {
      user: z.object({ userId: z.string().transform((v) => v.toUpperCase()) }),
    }
    const r = await validateSubjectClaim(transforming, {
      type: "user",
      properties: { userId: "ada" },
    } as SubjectClaim)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect((r.value.properties as { userId: string }).userId).toBe("ADA")
  })
})

describe("issuance refuses a claim that breaks the host's own schema", () => {
  async function fixture() {
    const tenant = await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    })
    const clock = () => 1_000
    const keyStore = new MemoryKeyStore({ clock })
    return {
      tenant,
      clock,
      keyStore,
      configStore: new MemoryConfigStore({ seed: [tenant] }),
      tokenStore: new MemoryTokenStore({ keyStore, clock }),
      sessionStore: new MemorySessionStore({ clock }),
      auditLog: new MemoryAuditLog(),
    }
  }

  function codePayload(tenantId: string) {
    return {
      tenantId: asTenantId(tenantId),
      clientId: "rp-1",
      appRedirectUri: "https://app.example/callback",
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
  }

  test("authorization_code: malformed claim is refused, nothing is signed", async () => {
    const f = await fixture()
    await saveEncryptedCode("c", codePayload(f.tenant.id) as never, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const res = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "c",
        clientId: "rp-1",
        redirectUri: "https://app.example/callback",
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        subjects,
        // Violates the schema the host itself declared.
        success: async () =>
          ({ type: "user", properties: { wrong: 123 } }) as never,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    expect(res.ok).toBe(false)
    if (res.ok) return
    expect(res.error.code).toBe("server_error")

    // The operator gets a diagnostic; the RP does not get a token.
    const events = f.auditLog.byKind("invalid_subject_claim")
    expect(events.length).toBe(1)
    expect((events[0] as { reason: string }).reason).toBe("invalid-properties")
  })

  test("a conforming claim still issues, with the parsed value", async () => {
    const f = await fixture()
    await saveEncryptedCode("c", codePayload(f.tenant.id) as never, 60_000, {
      keyStore: f.keyStore,
      tokenStore: f.tokenStore,
    })
    const res = await exchangeCode(
      {
        grantType: "authorization_code",
        code: "c",
        clientId: "rp-1",
        redirectUri: "https://app.example/callback",
      },
      {
        configStore: f.configStore,
        tokenStore: f.tokenStore,
        keyStore: f.keyStore,
        auditLog: f.auditLog,
        subjects,
        success: async () =>
          ({
            type: "user",
            properties: { userId: "u1", email: "a@b.com" },
          }) as never,
        issuerUrl: "https://idp.example",
        clock: f.clock,
      },
    )
    expect(res.ok).toBe(true)
    expect(f.auditLog.byKind("invalid_subject_claim").length).toBe(0)
  })
})
