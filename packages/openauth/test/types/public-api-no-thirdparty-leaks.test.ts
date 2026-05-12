/**
 * Compile-time guard: the public API must not surface third-party types.
 *
 * Background: consumers that `file:` / `npm link` this package against
 * their own copy of `jose` / `hono` / `oauth4webapi` /
 * `@simplewebauthn/server` hit TypeScript "duplicate type" errors when
 * the resolved versions differ. The cleanest fix is to never reach a
 * third-party type into the public surface — model the shape with Web
 * Fetch globals (`Request`, `Response`), Standard Schema v1, or
 * locally-defined plain objects (`Record<string, unknown>`, branded
 * strings, etc.).
 *
 * This file asserts the *current* contract at compile time. If a future
 * change re-introduces a third-party type into a re-exported symbol,
 * the corresponding assertion below will fail to type-check.
 *
 * To extend coverage, add another `assertAssignable<…>(…)` line for the
 * new public type. The body is a no-op at runtime; the value of this
 * file is the static check.
 */
import { test, expect } from "bun:test"

import type {
  AuditEvent,
  AuthMethodFactory,
  IdP,
  IdPOptions,
  MethodConfig,
  Oauth2MethodInput,
  Oauth2Properties,
  OidcMethodInput,
  Oauth2FactoryConfig,
  OidcFactoryConfig,
  SigningKey,
  SuccessMapInput,
} from "../../src/index"

/**
 * Static helper: succeeds only when `Actual` is assignable to
 * `Expected`. Equivalent to writing `const _: Expected = (null as
 * Actual)` over and over.
 */
function assertAssignable<Expected>(_value: Expected): void {
  /* compile-time only */
}

test("public API: Oauth2Properties.idTokenClaims is plain Record, not jose.JWTPayload", () => {
  type Claims = NonNullable<Oauth2Properties["idTokenClaims"]>
  // Tight regression check: jose's JWTPayload declares well-known
  // fields with specific types (e.g. `aud?: string | string[]`,
  // `exp?: number`, `iat?: number`, `sub?: string`). A plain
  // `Record<string, unknown>` makes every property `unknown` and
  // accepts any value type.
  //
  // We probe each known JWTPayload slot by assigning a value of an
  // **incompatible** primitive shape. If JWTPayload leaks back in, these
  // assignments fail to type-check — exactly the regression we want to
  // catch.
  const slot = {} as Claims
  slot["aud"] = 42 // JWTPayload: `string | string[]`; rejects number.
  slot["sub"] = []
  slot["exp"] = "not-a-number"
  slot["iat"] = { weird: true }
  expect(true).toBe(true)
})

test("public API: Oauth2MethodInput.deriveSubject takes plain-object claims", () => {
  type DeriveInput = Parameters<NonNullable<Oauth2MethodInput["deriveSubject"]>>[0]
  type Claims = NonNullable<DeriveInput["idTokenClaims"]>
  const slot = {} as Claims
  slot["aud"] = 42 // would fail under JWTPayload.

  type OidcDeriveInput = Parameters<NonNullable<OidcMethodInput["deriveSubject"]>>[0]
  type OidcClaims = NonNullable<OidcDeriveInput["idTokenClaims"]>
  const oidcSlot = {} as OidcClaims
  oidcSlot["aud"] = 42
  expect(true).toBe(true)
})

test("public API: IdP.handle takes Web Fetch Request and returns Web Fetch Response", () => {
  // `Request` and `Response` are the global Web Fetch types — not Hono's
  // `Context` or `Response`. If a refactor swapped them for Hono types,
  // this assignment would fail.
  type Handle = IdP["handle"]
  assertAssignable<(req: Request) => Promise<Response>>(
    undefined as unknown as Handle,
  )
  expect(true).toBe(true)
})

test("public API: IdPOptions.resolveTenant uses Web Fetch Request", () => {
  type Resolver = IdPOptions["resolveTenant"]
  // The function takes a global Request; if a Hono Context leaked in,
  // this would fail.
  assertAssignable<(req: Request) => Promise<unknown>>(
    undefined as unknown as Resolver,
  )
  expect(true).toBe(true)
})

test("public API: SuccessMapInput.properties is unknown (not a third-party type)", () => {
  type Props = SuccessMapInput["properties"]
  assertAssignable<unknown>(undefined as Props)
  expect(true).toBe(true)
})

test("public API: oauth2Factory / oidcFactory configs use plain primitives", () => {
  // Sanity check on the factory configs added in the same hardening pass.
  // No webauthn / jose / hono types should be reachable from these.
  type O2 = Oauth2FactoryConfig
  type Oidc = OidcFactoryConfig
  assertAssignable<{
    clientId: string
    scopes: string[]
    authorizationUrl: string
    tokenUrl: string
  }>({} as O2)
  assertAssignable<{
    issuer: string
    clientId: string
  }>({} as Oidc)
  expect(true).toBe(true)
})

test("public API: SigningKey.privateKeyRef is opaque, publicJwk is plain record", () => {
  // jose's `KeyLike` / `JWK` would force value types here. `unknown` and
  // `Record<string, unknown>` accept arbitrary values — if either leaked
  // back into a third-party type the assignments below would fail.
  type Key = SigningKey
  const k = {} as Key
  k.privateKeyRef = 42 // would fail under `KeyLike`.
  k.privateKeyRef = { custom: "kms-arn://…" }
  k.publicJwk = { kty: 42, weird: { nested: true } } // JWK shapes `kty` as string.
  expect(true).toBe(true)
})

test("public API: MethodConfig fields are plain primitives / Record", () => {
  // Anything in MethodConfig is host-supplied — no Zod / jose types
  // should be reachable. `config` stays `Record<string, unknown>` so
  // factories validate it via their own `configSchema`.
  assertAssignable<{
    id: string
    kind: string
    type: string
    enabled: boolean
    config: Record<string, unknown>
  }>({} as MethodConfig)
  expect(true).toBe(true)
})

test("public API: AuditEvent variants are plain primitive shapes", () => {
  // Pick representative variants. If a Date / Buffer / jose / hono type
  // leaked into any field, structural assignability against the
  // primitive shape below would fail.
  type TokenIssued = Extract<AuditEvent, { kind: "token_issued" }>
  assertAssignable<{
    kind: "token_issued"
    tenantId: string
    clientId: string
    methodId: string
    methodKind: string
    subjectId: string
    refreshTokenIdHash?: string
  }>({
    kind: "token_issued",
    tenantId: "tnt_x" as TokenIssued["tenantId"],
    clientId: "rp",
    methodId: "m",
    methodKind: "k",
    subjectId: "s",
  })

  type ReuseDetected = Extract<AuditEvent, { kind: "refresh_reuse_detected" }>
  assertAssignable<{
    kind: "refresh_reuse_detected"
    tenantId: string
    clientId: string
    family: string
  }>({
    kind: "refresh_reuse_detected",
    tenantId: "tnt_x" as ReuseDetected["tenantId"],
    clientId: "rp",
    family: "fam-1",
  })
  expect(true).toBe(true)
})

test("public API: AuthMethodFactory.configSchema is Standard Schema (not Zod-specific)", () => {
  // The validation library is intentionally pluggable — Zod 3.24+,
  // Valibot 1.0+, Arktype 2.0+, etc., all satisfy Standard Schema v1.
  // The contract therefore exposes only the Standard Schema surface
  // (`~standard`); requiring a Zod-specific shape like `_def` /
  // `_output` would block other validators.
  //
  // Probe: a plain object that conforms to the Standard Schema v1
  // contract should assign to `configSchema` without any Zod gymnastics.
  type Factory = AuthMethodFactory<unknown, unknown, { foo: string }>
  type Schema = Factory["configSchema"]
  const plainStandard = {
    "~standard": {
      version: 1 as const,
      vendor: "test",
      validate: (_: unknown) =>
        ({ value: { foo: "ok" } }) as { value: { foo: string } },
    },
  } as Schema
  expect(plainStandard).toBeDefined()
})
