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
  "persistent" | "transient" | "emailAddress" | "unspecified"

/**
 * One field's source. Either the assertion's NameID or a named
 * attribute. `format` narrows attribute lookup when an IdP issues
 * multiple attributes with the same `Name` but different `NameFormat`.
 */
export type SamlAttributeRef =
  { source: "nameId" } | { source: "attribute"; name: string; format?: string }

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
  /**
   * Accept `<saml:EncryptedAssertion>` responses. **Off by default** —
   * a connection only opts in when its IdP is configured to encrypt.
   * When `false`, an encrypted assertion is rejected (the SP advertises
   * no decryption cert and node-saml has no `decryptionPvk`). Requires
   * `decryptionKey` when `true` (enforced by `configSchema`).
   */
  allowEncryptedAssertions?: boolean
  /**
   * Per-connection SP **decryption** keypair — the private half the IdP
   * encrypts assertions to. Same SAML-AD O3 rationale as `signingKey`:
   * decoupled from the OIDC `KeyStore` (the IdP pins the matching cert
   * via SP metadata; rotation is an IdP-coordination event;
   * KMS-agnostic). Required iff `allowEncryptedAssertions` is `true`.
   * Treat `privateKeyPem` as a secret: the host should encrypt the
   * `MethodStore` at rest (or supply it via its own resolver) — same
   * handling as `signingKey.privateKeyPem` and any per-tenant
   * credential. `certPem` is the matching X.509 cert the IdP encrypts
   * to; SP metadata advertises it as a `use="encryption"`
   * `KeyDescriptor` (same advertise-only-what-we-serve invariant as
   * `signingKey`).
   */
  decryptionKey?: { privateKeyPem: string; certPem: string }
  idpInitiated?: SamlIdpInitiatedConfig
  /** Clock skew allowance for `NotBefore` / `NotOnOrAfter`. Seconds. */
  clockSkewSeconds?: number
  /**
   * Override the derived SP entityID.
   *
   * By default the entityID is derived as
   * `<issuerUrl>/<tenantId>/<methodId>` (SAML-AD5) — stable, no config
   * required, and guaranteed to match what SP metadata publishes. Set
   * this **only** to adopt an entityID that already exists at the IdP,
   * so an existing SAML app can be migrated without the customer
   * editing their production SSO config.
   *
   * The override flows through every consumer at once — `AuthnRequest`
   * issuer, `AudienceRestriction` validation, SP metadata, and logout
   * messages — so the anti-drift invariant holds either way. Changing
   * it on a live connection invalidates the IdP-side trust config;
   * treat it as an IdP-coordination event.
   */
  spEntityId?: string
  /**
   * Set `ForceAuthn="true"` on the outbound `AuthnRequest`, asking the
   * IdP to re-authenticate the user even if it has a live session.
   * Default `false`.
   *
   * Note that this is a *request*: SAML gives the IdP no obligation to
   * honour it, and there is no way to verify from the Response that it
   * did. Do not treat a successful assertion as proof of fresh
   * authentication.
   */
  forceAuthn?: boolean
  /**
   * Request specific authentication context classes (e.g. MFA) from
   * the IdP via `<RequestedAuthnContext>`.
   *
   * **Omitted ⇒ no `RequestedAuthnContext` element is sent at all**,
   * which lets the IdP apply its own sign-on policy. That is the right
   * default for nearly every deployment: a `RequestedAuthnContext` the
   * IdP cannot satisfy exactly is answered with `NoAuthnContext`
   * instead of a login, and an MFA policy at the IdP is a common way
   * to *not* satisfy `PasswordProtectedTransport` under
   * `Comparison="exact"`.
   *
   * Set it only when the IdP has told you which class refs it honours.
   * `comparison` maps to the `Comparison` attribute and defaults to
   * `"exact"`; `"minimum"` is usually the safer choice when requesting
   * MFA.
   *
   * Requesting a context does **not** verify one was used — read
   * `SamlSpProperties.authnContextClassRef` for what the IdP actually
   * asserted.
   */
  requestedAuthnContext?: {
    /** Full URNs, e.g. `urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthn`. */
    classRefs: ReadonlyArray<string>
    comparison?: "exact" | "minimum" | "maximum" | "better"
  }
  /**
   * Require the `<saml:Assertion>` itself to carry a valid XML-DSig.
   * **Defaults to `true` and should stay that way** — the identity,
   * conditions, and audience all live inside the assertion, so signing
   * it is what actually binds them.
   *
   * Set `false` only for an IdP that signs the outer `<Response>` and
   * nothing else, and only together with `requireSignedResponse: true`.
   * The schema refuses to let both be off.
   */
  requireSignedAssertion?: boolean
  /**
   * Require the outer `<samlp:Response>` to carry a valid XML-DSig.
   * Default `false` — requiring it is stricter than the Okta / Entra
   * default and would reject the majority of real IdPs. Enable it for
   * an IdP that signs the Response, either as defence in depth
   * alongside a signed assertion or (with
   * `requireSignedAssertion: false`) as the only signature on offer.
   */
  requireSignedResponse?: boolean
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
  /**
   * Unix ms — the `AuthnStatement/@SessionNotOnOrAfter` the IdP
   * asserted, when it supplied one. This is the IdP's own view of when
   * its session for this user expires.
   *
   * The library does **not** act on it: token and session lifetimes are
   * host policy, and this library owns no session. Hosts that want
   * "when their IdP session ends, ours ends" should clamp their own
   * session/token TTL to this value in the `success` callback.
   */
  sessionNotOnOrAfter?: number
  /**
   * The `AuthnContext/AuthnContextClassRef` the IdP actually asserted —
   * i.e. how it says it authenticated the user. Absent when the
   * assertion carries none.
   *
   * This is the value to check for step-up decisions ("was this really
   * MFA?"). `SamlSpConfig.requestedAuthnContext` only *asks*; this is
   * the answer, and the two can differ.
   */
  authnContextClassRef?: string
  raw: {
    responseXml: string
  }
}
