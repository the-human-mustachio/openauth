/**
 * SAML SP — public types.
 *
 * These types are the locked contract for the SAML SP method family and
 * are intentionally introduced ahead of the runtime implementation so
 * downstream callers can import them today, and so the public-API
 * leak guard
 * (`test/types/saml-sp-no-thirdparty-leaks.test.ts`) can verify
 * the shapes before any `@node-saml/*` or `xml-crypto` code lands.
 *
 * No third-party types appear here. `@node-saml/node-saml`'s `Profile`
 * is mapped onto `SamlSpProperties` at the wrapper boundary; consumers
 * never see node-saml's surface.
 *
 * See `docs/plans/claude/saml-sp-plan.md` for the architectural
 * decisions (SAML-AD1–AD7) backing this shape.
 */

/**
 * Standard SAML 2.0 NameID formats we support.
 *
 *   - `persistent`     — opaque, stable per user/SP pair; preferred.
 *   - `transient`      — opaque, single-session.
 *   - `emailAddress`   — RFC 822 email; common with legacy IdPs.
 *   - `unspecified`    — IdP picks; pass through verbatim.
 */
export type SamlNameIdFormat =
  | "persistent"
  | "transient"
  | "emailAddress"
  | "unspecified"

/**
 * One field's source. Either the assertion's NameID or a named
 * attribute. `format` narrows attribute lookup when an IdP issues
 * multiple attributes with the same `Name` but different `NameFormat`.
 */
export type SamlAttributeRef =
  | { source: "nameId" }
  | { source: "attribute"; name: string; format?: string }

/**
 * How the SAML method translates a verified assertion into the
 * `providerSubject` + per-claim fields that flow into the host's
 * `success` callback. Mirrors the OIDC method's claim-mapping
 * configuration — the host owns the final `SubjectClaim`; this map
 * just normalises the SAML side.
 */
export type SamlAttributeMapping = {
  /** Which attribute becomes `providerSubject`. Defaults to NameID. */
  subject?: SamlAttributeRef
  email?: SamlAttributeRef
  /** SAML assertions are typically issued only after IdP-side verification. */
  emailVerified?: { source: "literal"; value: boolean }
  name?: SamlAttributeRef
  /** Multi-valued — the mapper preserves array shape. */
  groups?: SamlAttributeRef
  /** Pass-through map for additional claims hosts want surfaced. */
  custom?: Record<string, SamlAttributeRef>
}

/**
 * A single PEM-encoded IdP signing certificate, optionally bounded by a
 * validity window. The runtime verifier accepts any cert whose window
 * covers `now` — supports overlapping hot rotation without re-deploys.
 */
export type SamlIdpSigningCert = {
  pem: string
  /** Inclusive lower bound. Unix ms. Omit for no lower bound. */
  notBefore?: number
  /** Exclusive upper bound. Unix ms. Omit for no upper bound. */
  notAfter?: number
}

/**
 * Identity-Provider-side configuration the host paste/imports from the
 * IdP's metadata XML (or uploads a metadata URL we fetch once). Stable
 * across deploys — keyed by `(tenantId, methodId)` in `MethodStore`.
 */
export type SamlIdpConfig = {
  entityId: string
  /** SSO endpoint URL. HTTP-Redirect binding is the default. */
  ssoUrl: string
  /** Single Logout endpoint URL. Optional; Phase 3 deliverable. */
  sloUrl?: string
  /** Preferred NameID format requested in `AuthnRequest`. */
  nameIdFormat?: SamlNameIdFormat
  /** One or more IdP signing certs. ≥1 required. Hot-rotatable. */
  signingCerts: ReadonlyArray<SamlIdpSigningCert>
}

/**
 * IdP-initiated SSO binding. When set, the ACS endpoint accepts
 * unsolicited SAML Responses (no `InResponseTo`) and synthesizes a
 * flow record using these defaults so the existing
 * `MethodResult.success` path can run end-to-end.
 *
 * Documented in plan SAML-AD7 — this is the one architectural carve-out
 * SAML imposes on the framework. Omit to reject unsolicited Responses
 * with `invalid_request` (the conservative default).
 */
export type SamlIdpInitiatedConfig = {
  defaultClientId: string
  defaultRedirectUri: string
  defaultScopes?: string[]
}

/**
 * Tenant-supplied configuration for a SAML SP method instance.
 * Validated by `samlSpFactory.configSchema` (Standard Schema v1).
 */
export type SamlSpConfig = {
  idp: SamlIdpConfig
  attributeMapping: SamlAttributeMapping
  /** Whether to sign outbound `AuthnRequest`. Default `false`. */
  signAuthnRequest?: boolean
  /**
   * Per-connection SP signing keypair (SAML-AD: O3). **Decoupled from
   * the OIDC `KeyStore` on purpose** — the SP signing cert is pinned at
   * the IdP and rotated as an IdP-coordination event, not on the OIDC
   * token-key schedule; this also keeps the design KMS-agnostic.
   * `privateKeyPem` signs the `AuthnRequest`; `certPem` is what the IdP
   * pins and what SP metadata advertises. Required iff
   * `signAuthnRequest` is `true`. Treat `privateKeyPem` as a secret:
   * the host should encrypt the `MethodStore` at rest (or supply it via
   * its own resolver) — same handling as any per-tenant credential.
   */
  signingKey?: { privateKeyPem: string; certPem: string }
  idpInitiated?: SamlIdpInitiatedConfig
  /** Clock skew allowance for `NotBefore` / `NotOnOrAfter`. Seconds. */
  clockSkewSeconds?: number
}

/**
 * Method-private state stashed in `FlowRecord.methodState` for the
 * duration of an SP-initiated flow.
 *
 * `InResponseTo` correlation is handled out-of-band by node-saml's
 * `CacheProvider` (backed by `methodScratch`), so the outstanding
 * request id does **not** live here — only the framework state
 * envelope echoed as RelayState and the issuance timestamp.
 */
export type SamlSpState = {
  relayState: string
  issuedAt: number
  /**
   * SP entityID + ACS URL computed at AuthnRequest time, where the
   * framework's dispatch context is available. The ACS dispatch has
   * no dispatch context, so these are read back from here to validate
   * the assertion's `AudienceRestriction` / `Recipient` against the
   * exact values the IdP saw in the request.
   */
  spEntityId: string
  acsUrl: string
}

/**
 * Properties handed to the host's `IdPOptions.success` callback on a
 * successful SAML authentication. The host translates these into the
 * final `SubjectClaim` it owns.
 *
 * `raw.responseXml` is provided as an escape hatch for hosts that want
 * to inspect the verified Response themselves; the wrapper has already
 * run the full signature gauntlet by the time these properties leave
 * the method.
 */
export type SamlSpProperties = {
  nameId: {
    value: string
    format: SamlNameIdFormat
  }
  attributes: Record<string, string | string[]>
  /** Used for Single Logout correlation (Phase 3). */
  sessionIndex?: string
  /** Unix ms — the assertion's `AuthnInstant`. */
  authnInstant: number
  raw: {
    responseXml: string
  }
}
