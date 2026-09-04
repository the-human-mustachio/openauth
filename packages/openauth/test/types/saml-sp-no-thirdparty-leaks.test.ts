/**
 * Compile-time guard for the SAML SP subpath
 * (`@_mustachio/openauth/methods/saml-sp`).
 *
 * Twin objective:
 *
 *   1. The subpath's public types describe SAML data using plain
 *      primitives / records — no `@node-saml/node-saml`, `xml-crypto`,
 *      `@xmldom/xmldom`, `xml2js`, etc. types appear in the surface.
 *      If a future refactor leaks (say) `node-saml`'s `Profile` into
 *      `SamlSpProperties`, the assertions below stop type-checking.
 *
 *   2. The library's **root** entry (`@_mustachio/openauth`) does not
 *      re-export any SAML symbol. That keeps the root edge-clean by
 *      construction — Workers / browsers can keep importing the root
 *      without ever loading `node:crypto`-dependent code.
 *
 * To extend coverage, add another `assertAssignable<…>(…)` line for a
 * new SAML type. To verify the root stays clean, add a `// @ts-expect-error`
 * import probe below.
 *
 * See `docs/plans/claude/saml-sp-plan.md` SAML-AD2 (Node-only export).
 */
import { test, expect } from "bun:test"

import type {
  SamlAttributeMapping,
  SamlAttributeRef,
  SamlIdpConfig,
  SamlIdpInitiatedConfig,
  SamlIdpSigningCert,
  SamlNameIdFormat,
  SamlSpConfig,
  SamlSpProperties,
  SamlSpState,
  samlSpFactory,
} from "../../src/methods/saml-sp"

import type * as RootApi from "../../src/index"

function assertAssignable<Expected>(_value: Expected): void {
  /* compile-time only */
}

test("SAML SP: SamlNameIdFormat is the locked closed union", () => {
  assertAssignable<
    "persistent" | "transient" | "emailAddress" | "unspecified"
  >("persistent" as SamlNameIdFormat)
  expect(true).toBe(true)
})

test("SAML SP: SamlSpConfig.idp.signingCerts is plain PEM strings (no KeyLike)", () => {
  // node-saml / xml-crypto would tend to model certs as Buffer or
  // crypto.KeyLike. The contract is intentionally a plain PEM string.
  type Cert = SamlIdpSigningCert
  const slot = {} as Cert
  slot.pem = "totally-fake-pem"
  // Numbers would fail under any third-party KeyLike or Buffer-based shape.
  slot.notBefore = 1_700_000_000_000
  slot.notAfter = 1_800_000_000_000
  // Reject obvious foreign primitives.
  // @ts-expect-error — `pem` must be string, never Buffer-like.
  slot.pem = { type: "Buffer", data: [] }
  expect(true).toBe(true)
})

test("SAML SP: SamlIdpConfig fields are plain primitives", () => {
  assertAssignable<{
    entityId: string
    ssoUrl: string
    signingCerts: ReadonlyArray<{ pem: string }>
  }>({} as SamlIdpConfig)
  expect(true).toBe(true)
})

test("SAML SP: SamlAttributeRef is a locked discriminated union", () => {
  // No regex / Buffer / xpath-library types should leak in.
  const a: SamlAttributeRef = { source: "nameId" }
  const b: SamlAttributeRef = {
    source: "attribute",
    name: "http://schemas.example/email",
  }
  const c: SamlAttributeRef = {
    source: "attribute",
    name: "groups",
    format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
  }
  expect([a, b, c].length).toBe(3)
})

test("SAML SP: SamlAttributeMapping accepts plain refs and a literal email-verified", () => {
  const mapping: SamlAttributeMapping = {
    subject: { source: "nameId" },
    email: { source: "attribute", name: "email" },
    emailVerified: { source: "literal", value: true },
    groups: { source: "attribute", name: "groups" },
    custom: {
      department: { source: "attribute", name: "dept" },
    },
  }
  expect(mapping).toBeDefined()
})

test("SAML SP: SamlIdpInitiatedConfig is plain primitives", () => {
  assertAssignable<{
    defaultClientId: string
    defaultRedirectUri: string
  }>({} as SamlIdpInitiatedConfig)
  expect(true).toBe(true)
})

test("SAML SP: SamlSpConfig is plain primitives, signingKey is plain PEM strings", () => {
  const cfg = {} as SamlSpConfig
  // O3: per-connection PEM keypair (decoupled from KeyStore), NOT a
  // jose KeyLike / node-saml privateKey object — plain strings only.
  cfg.signingKey = {
    privateKeyPem: "-----BEGIN PRIVATE KEY-----\n…",
    certPem: "-----BEGIN CERTIFICATE-----\n…",
  }
  // A number wouldn't satisfy any third-party KeyLike contract; this
  // explicit reject confirms the shape is exactly plain PEM strings.
  // @ts-expect-error — `signingKey.privateKeyPem` must be a string.
  cfg.signingKey = { privateKeyPem: 42, certPem: "x" }
  cfg.clockSkewSeconds = 60
  expect(true).toBe(true)
})

test("SAML SP: SamlSpState is plain primitives (no XML Document type)", () => {
  assertAssignable<{
    relayState: string
    issuedAt: number
    spEntityId: string
    acsUrl: string
  }>({} as SamlSpState)
  expect(true).toBe(true)
})

test("SAML SP: SamlSpProperties exposes attributes as plain string/string[] map", () => {
  type Attrs = SamlSpProperties["attributes"]
  // A plain `Record<string, string | string[]>` accepts arbitrary
  // strings. node-saml's Profile types would force specific shapes.
  const slot = {} as Attrs
  slot["email"] = "user@example.com"
  slot["groups"] = ["a", "b"]
  // Any object value should be rejected.
  // @ts-expect-error — attributes are strings or string arrays only.
  slot["nope"] = { complex: "shape" }
  expect(true).toBe(true)
})

test("SAML SP: SamlSpProperties.raw exposes responseXml as a plain string", () => {
  // Critical: NOT a Document, NodeList, XMLDocument, or any other
  // xmldom type. The escape hatch is the raw XML text.
  type Raw = SamlSpProperties["raw"]
  assertAssignable<{ responseXml: string }>({} as Raw)
  expect(true).toBe(true)
})

test("SAML SP: samlSpFactory.configSchema is Standard Schema (not Zod-specific)", () => {
  // Same constraint as oauth2Factory / oidcFactory — the validation
  // library is pluggable.
  type Schema = typeof samlSpFactory.configSchema
  const plainStandard = {
    "~standard": {
      version: 1 as const,
      vendor: "test",
      validate: () => ({ value: {} as SamlSpConfig }),
    },
  } as Schema
  expect(plainStandard).toBeDefined()
})

test("SAML SP: root @_mustachio/openauth entry does NOT re-export SAML symbols", () => {
  // The whole point of the Node-only subpath is to keep the root edge-
  // clean. If a future refactor re-exports `samlSpFactory` (or any
  // SAML type) from `src/index.ts`, the following `@ts-expect-error`
  // lines stop erroring, the test fails, and we catch the regression
  // before it ships.
  //
  // We probe each SAML public symbol. Each MUST be unreachable from
  // the root entry.

  // @ts-expect-error — root must not export `samlSpFactory`.
  type _A = RootApi.samlSpFactory
  // @ts-expect-error — root must not export `SamlSpConfig`.
  type _B = RootApi.SamlSpConfig
  // @ts-expect-error — root must not export `SamlSpProperties`.
  type _C = RootApi.SamlSpProperties
  // @ts-expect-error — root must not export `SamlSpState`.
  type _D = RootApi.SamlSpState
  // @ts-expect-error — root must not export `SamlIdpConfig`.
  type _E = RootApi.SamlIdpConfig
  // @ts-expect-error — root must not export `SamlAttributeMapping`.
  type _F = RootApi.SamlAttributeMapping
  // @ts-expect-error — root must not export `SamlNameIdFormat`.
  type _G = RootApi.SamlNameIdFormat
  // @ts-expect-error — root must not export `SamlAttributeRef`.
  type _H = RootApi.SamlAttributeRef
  // @ts-expect-error — root must not export `SamlIdpInitiatedConfig`.
  type _I = RootApi.SamlIdpInitiatedConfig
  // @ts-expect-error — root must not export `SamlIdpSigningCert`.
  type _J = RootApi.SamlIdpSigningCert

  // Reference each to keep TypeScript honest about the @ts-expect-error.
  void (null as unknown as _A)
  void (null as unknown as _B)
  void (null as unknown as _C)
  void (null as unknown as _D)
  void (null as unknown as _E)
  void (null as unknown as _F)
  void (null as unknown as _G)
  void (null as unknown as _H)
  void (null as unknown as _I)
  void (null as unknown as _J)
  expect(true).toBe(true)
})
