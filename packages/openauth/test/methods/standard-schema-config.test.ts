/**
 * Lock-in test for `AuthMethodFactory.configSchema` accepting any
 * Standard Schema v1 implementation — not just Zod.
 *
 * We use Valibot (already a devDependency) to exercise the non-Zod
 * path end-to-end:
 *   1. Build a factory whose configSchema is a `valibot` object schema.
 *   2. Drive `/authorize` through the IdP with a tenant whose
 *      `MethodConfig.config` matches that schema.
 *   3. Drive a separate negative case where `MethodConfig.config`
 *      violates the schema and verify the framework rejects the load.
 *
 * If this test breaks because `configSchema` was retyped to a
 * Zod-specific shape, the regression is exactly what this case exists
 * to catch.
 */
import { describe, expect, test } from "bun:test"
import * as v from "valibot"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { s256Challenge } from "../../src/domain/pkce"
import type {
  AuthMethod,
  AuthMethodFactory,
  MethodContext,
  MethodResult,
} from "../../src/types/method"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"
import { ok } from "../../src/types/result"

import { buildStateKeys } from "../helpers/state-keys"
import { authorizeUrl } from "../helpers/idp"
import { testSubjects } from "../helpers/subjects"

type ValibotProps = { greeting: string }
type ValibotConfig = { greeting: string; loud?: boolean }

const valibotConfigSchema = v.object({
  greeting: v.pipe(v.string(), v.minLength(1)),
  loud: v.optional(v.boolean()),
})

const valibotFactory: AuthMethodFactory<ValibotProps, unknown, ValibotConfig> =
  {
    kind: "valibot-stub",
    configSchema: valibotConfigSchema,
    build: async ({
      id,
      kind,
      config,
    }): Promise<AuthMethod<ValibotProps, unknown>> => ({
      id,
      kind,
      type: "custom",
      routes: {
        "GET /authorize": async (
          _ctx: MethodContext<unknown>,
        ): Promise<MethodResult<ValibotProps, unknown>> => ({
          kind: "success",
          providerSubject: "valibot-subject",
          properties: {
            greeting: config.loud
              ? config.greeting.toUpperCase()
              : config.greeting,
          },
        }),
      },
    }),
  }

function tenant(config: Record<string, unknown>): TenantConfig {
  return {
    id: asTenantId("valibot-tenant"),
    displayName: "Valibot Tenant",
    clients: [
      {
        id: "rp-1",
        name: "RP",
        type: "public",
        redirectUris: ["https://app.example/callback"],
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["openid"],
        pkceRequired: true,
      },
    ],
    methods: [
      {
        id: "valibot-stub",
        kind: "valibot-stub",
        type: "custom",
        enabled: true,
        config,
      },
    ],
  }
}

function buildIdp(t: TenantConfig) {
  return createIdP({
    resolveTenant: async () => ok(t.id),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [t] }),
    keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
    tokenStore: new MemoryTokenStore({
      keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
      clock: () => Date.now(),
    }),
    sessionStore: new MemorySessionStore({ clock: () => Date.now() }),
    auditLog: new MemoryAuditLog(),
    issuerUrl: "https://idp.example",
    methods: { "valibot-stub": valibotFactory as never },
    subjects: testSubjects,
    success: async ({ properties }) =>
      ({ type: "user", properties: properties as object }) as never,
  })
}

describe("AuthMethodFactory.configSchema accepts any Standard Schema v1 impl", () => {
  test("valibot-validated config drives /authorize successfully", async () => {
    const idp = buildIdp(tenant({ greeting: "hello", loud: true }))
    const challenge = await s256Challenge("v".repeat(48))
    const res = await idp.handle(
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
    // The stub returns kind:"success" → 302 to RP with an auth code.
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get("location")!)
    expect(loc.origin + loc.pathname).toBe("https://app.example/callback")
    expect(loc.searchParams.get("code")).toBeString()
  })

  test("valibot rejection: config violating schema → method_not_found + audit", async () => {
    const auditLog = new MemoryAuditLog()
    const t = tenant({ greeting: "" }) // empty string violates minLength(1)
    const idp = createIdP({
      resolveTenant: async () => ok(t.id),
      stateKeys: buildStateKeys(),
      configStore: new MemoryConfigStore({ seed: [t] }),
      keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
      tokenStore: new MemoryTokenStore({
        keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
        clock: () => Date.now(),
      }),
      sessionStore: new MemorySessionStore({ clock: () => Date.now() }),
      auditLog,
      issuerUrl: "https://idp.example",
      methods: { "valibot-stub": valibotFactory as never },
      subjects: testSubjects,
      success: async ({ properties }) =>
        ({ type: "user", properties: properties as object }) as never,
    })
    const challenge = await s256Challenge("v".repeat(48))
    const res = await idp.handle(
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
    expect(res.status).toBeGreaterThanOrEqual(400)
    // The invalid_method_config audit fires from MethodCache before the
    // method ever runs.
    expect(auditLog.byKind("invalid_method_config").length).toBe(1)
  })
})
