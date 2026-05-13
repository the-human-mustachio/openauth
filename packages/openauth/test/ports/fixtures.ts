/**
 * Shared fixtures + helpers for the parameterized port-conformance suite.
 *
 * Each port suite (`describeTokenStore`, `describeSessionStore`, ...) takes
 * adapter factories and runs the same set of cases against any adapter. An
 * adapter that fails any test in the conformance suite is **not certified**
 * for production per `ports/CONSISTENCY.md`.
 */
import type { FlowRecord } from "../../src/types/flow"
import { asTenantId } from "../../src/types/tenant"
import type { TenantConfig } from "../../src/types/tenant"
import type { CodePayload, RefreshTokenPayload } from "../../src/types/token"
import type { SubjectClaim } from "../../src/types/subject"

export const fixtureTenantId = asTenantId("acme")

/**
 * Controllable clock — adapter conformance tests that exercise TTL / expiry
 * paths advance time deterministically rather than sleeping.
 */
export type TestClock = {
  now: () => number
  advance: (ms: number) => void
  set: (ms: number) => void
}

export function testClock(start = 1_700_000_000_000): TestClock {
  let t = start
  return {
    now: () => t,
    advance: (ms) => {
      t += ms
    },
    set: (ms) => {
      t = ms
    },
  }
}

export function makeCodePayload(
  overrides: Partial<CodePayload> = {},
): CodePayload {
  return {
    tenantId: fixtureTenantId,
    clientId: "rp-1",
    appRedirectUri: "https://app.example/cb",
    appState: "rp-state",
    scopes: ["openid"],
    audience: undefined,
    clientPkce: { challenge: "abc", method: "S256" },
    methodId: "google-workspace",
    methodKind: "google",
    context: null,
    providerSubject: "ps-google-123",
    properties: { email: "ada@example.com" },
    authTime: Math.floor(Date.now() / 1000),
    expiresAt: Date.now() + 60_000,
    ...overrides,
  }
}

export function makeRefreshPayload(
  overrides: Partial<RefreshTokenPayload> = {},
): RefreshTokenPayload {
  const claim: SubjectClaim = {
    type: "user",
    properties: { userId: "u1" },
  } as SubjectClaim
  return {
    tenantId: fixtureTenantId,
    clientId: "rp-1",
    subjectId: "subj-1",
    claim,
    scopes: ["openid"],
    family: "fam-1",
    methodId: "test-method",
    methodKind: "test-kind",
    authTime: Math.floor(Date.now() / 1000),
    issuedAt: Date.now(),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
    ...overrides,
  }
}

export function makeFlow(overrides: Partial<FlowRecord> = {}): FlowRecord {
  return {
    flowId: "flow-1",
    tenantId: fixtureTenantId,
    methodId: "google-workspace",
    methodKind: "google",
    clientId: "rp-1",
    appRedirectUri: "https://app.example/cb",
    callbackPath: "/cb/google-workspace",
    callbackHost: "idp.example",
    appState: null,
    scopes: ["openid"],
    responseType: "code",
    nonce: "nonce-1",
    methodState: null,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000,
    ...overrides,
  }
}

export function makeTenantConfig(
  overrides: Partial<TenantConfig> = {},
): TenantConfig {
  return {
    id: fixtureTenantId,
    displayName: "Acme",
    clients: [
      {
        id: "rp-1",
        name: "Acme RP",
        type: "public",
        redirectUris: ["https://app.example/cb"],
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["openid"],
        pkceRequired: true,
      },
    ],
    methods: [],
    ...overrides,
  }
}

/**
 * Unique-suffix helper — keeps adapter tests that hit a persistent backend
 * (PGlite, miniflare) from colliding when the same describe block runs
 * across multiple files.
 */
let suffixCounter = 0
export function uniqueSuffix(prefix = "x"): string {
  suffixCounter += 1
  return `${prefix}-${Date.now().toString(36)}-${suffixCounter}`
}
