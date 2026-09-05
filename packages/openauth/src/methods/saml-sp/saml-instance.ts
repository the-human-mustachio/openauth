/**
 * Construct a `@node-saml/node-saml` `SAML` instance from validated
 * `SamlSpConfig` plus the per-request binding context (SP entityID +
 * ACS URL, both derived at dispatch time per SAML-AD5).
 *
 * CJS interop: node-saml is CommonJS-only. Per the SAML house-style
 * note, default-import then destructure rather than relying on the
 * named-export heuristic.
 */
import nodeSaml from "@node-saml/node-saml"

import type { MethodScratch } from "../../types/method"

import { methodScratchCacheProvider } from "./cache-provider"
import { selectActiveCertPems } from "./cert-rotation"
import type { SamlNameIdFormat, SamlSpConfig } from "./types"

const { SAML, ValidateInResponseTo } = nodeSaml
type SamlInstance = InstanceType<typeof SAML>

/** Standard SAML 2.0 NameID format URNs. */
export const NAME_ID_FORMAT_URN: Record<SamlNameIdFormat, string> = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
}

/**
 * Outstanding-request-id cache TTL. Must comfortably outlast the
 * slowest realistic IdP login screen; the flow record expires on its
 * own shorter clock, so this is just the upper bound on how long an
 * `InResponseTo` stays accepted.
 */
const IN_RESPONSE_TO_TTL_MS = 60 * 60 * 1000

export type SamlBindingContext = {
  /** SP entityID — `<issuerUrl>/<tenantId>/<methodId>` (SAML-AD5). */
  spEntityId: string
  /** ACS URL — the framework's `/cb/<methodId>` universal callback. */
  acsUrl: string
  /** Per-request scratch backing the `InResponseTo` cache. */
  scratch: MethodScratch
  /**
   * IdP-initiated mode. An unsolicited Response has no `InResponseTo`
   * (there was no AuthnRequest), so `validateInResponseTo` must be
   * `ifPresent` rather than `always` — otherwise node-saml throws
   * "InResponseTo is missing". Signature / Issuer / Audience /
   * Conditions are still fully enforced; assertion-ID replay dedup is
   * layered on top by the caller (node-saml does not dedup unsolicited
   * assertion IDs). Default `false` ⇒ SP-initiated, `always`
   * (unchanged).
   */
  idpInitiated?: boolean
  /**
   * Logout-binding instance (the `/sls` + `/logout` paths). node-saml's
   * `InResponseTo` machinery only reads the attribute off a `Response`
   * root, never a `LogoutResponse`, so with the default `always` it
   * throws "InResponseTo is missing" on every inbound `LogoutResponse`.
   * Front-channel logout correlation is out of that scope — we
   * replay-dedup the inbound `LogoutRequest @ID` via `methodScratch`
   * instead — so logout instances use `never`. Overrides `idpInitiated`.
   */
  logout?: boolean
  /**
   * Per-connection SP signing material (SAML-AD: O3 — decoupled from
   * the OIDC `KeyStore`; the IdP pins this cert, rotation is an
   * IdP-coordination event). Present ⇒ node-saml signs the outbound
   * `AuthnRequest` (HTTP-Redirect binding) **and** outbound logout
   * messages (`LogoutRequest` / `LogoutResponse`) with it.
   */
  signing?: {
    privateKeyPem: string
    certPem: string
  }
  /**
   * IdP Single Logout endpoint (`SamlSpConfig.idp.sloUrl`). Destination
   * for SP-emitted `LogoutResponse` (front-channel SLO, Phase 3) and
   * SP-initiated `LogoutRequest`. Only needed on the `/sls` path; the
   * SSO paths leave it unset.
   */
  logoutUrl?: string
  /**
   * SP decryption private key PEM (`SamlSpConfig.decryptionKey`),
   * passed through to node-saml's `decryptionPvk`. Present ⇒ node-saml
   * decrypts `<saml:EncryptedAssertion>` (the decrypted assertion's
   * XML-DSig is still fully enforced). Set only when the connection
   * opted into `allowEncryptedAssertions`; absent ⇒ an encrypted
   * assertion is rejected.
   */
  decryptionPvk?: string
}

/**
 * Derive the per-instance SP entityID. Stable across deploys for a
 * given `(issuerUrl, tenantId, methodId)` triple so IdP-side trust
 * config doesn't churn.
 */
export function deriveSpEntityId(
  issuerUrl: string,
  tenantId: string,
  methodId: string,
): string {
  const base = issuerUrl.endsWith("/") ? issuerUrl.slice(0, -1) : issuerUrl
  return `${base}/${tenantId}/${methodId}`
}

/**
 * The SP entityID this connection actually presents — the configured
 * override if the operator set one (to adopt an entityID that already
 * exists at the IdP), else the derived default.
 *
 * **Every** consumer must go through this one function: the
 * `AuthnRequest` issuer, `AudienceRestriction` validation, SP metadata,
 * and logout messages all have to agree, or the IdP rejects us. That
 * shared-resolution property is what the metadata anti-drift test
 * guards.
 */
export function resolveSpEntityId(
  config: SamlSpConfig,
  issuerUrl: string,
  tenantId: string,
  methodId: string,
): string {
  return config.spEntityId ?? deriveSpEntityId(issuerUrl, tenantId, methodId)
}

export function buildSamlInstance(
  config: SamlSpConfig,
  binding: SamlBindingContext,
  nowMs: number,
): SamlInstance {
  const activeCerts = selectActiveCertPems(config.idp.signingCerts, nowMs)
  if (activeCerts.length === 0) {
    throw new Error(
      "saml-sp: no IdP signing certificate is currently within its " +
        "validity window — check SamlSpConfig.idp.signingCerts notBefore/notAfter.",
    )
  }

  const identifierFormat =
    config.idp.nameIdFormat !== undefined
      ? NAME_ID_FORMAT_URN[config.idp.nameIdFormat]
      : null

  return new SAML({
    // MandatorySamlOptions
    idpCert: activeCerts,
    issuer: binding.spEntityId,
    callbackUrl: binding.acsUrl,
    // IdP endpoints
    entryPoint: config.idp.ssoUrl,
    idpIssuer: config.idp.entityId,
    audience: binding.spEntityId,
    identifierFormat,
    // Security posture. A signed *assertion* is mandatory (identity +
    // conditions + audience all live in the signed bytes); requiring
    // the outer Response to also be signed is stricter than the
    // Okta/Entra default and would reject the majority of real IdPs,
    // so it is not required here. SP-initiated requires an outstanding
    // InResponseTo (`always`); IdP-initiated is unsolicited so it must
    // be `ifPresent` — the caller layers explicit assertion-ID replay
    // dedup on top for that mode.
    validateInResponseTo: binding.logout
      ? ValidateInResponseTo.never
      : binding.idpInitiated
        ? ValidateInResponseTo.ifPresent
        : ValidateInResponseTo.always,
    wantAssertionsSigned: config.requireSignedAssertion ?? true,
    wantAuthnResponseSigned: config.requireSignedResponse ?? false,
    acceptedClockSkewMs: (config.clockSkewSeconds ?? 60) * 1000,
    // ForceAuthn — a request, never a guarantee. SAML gives the IdP no
    // obligation to honour it and the Response carries no proof either
    // way, so nothing downstream may treat it as freshness evidence.
    forceAuthn: config.forceAuthn ?? false,
    // RequestedAuthnContext. node-saml's own defaults are
    // `disableRequestedAuthnContext: false` +
    // `authnContext: [PasswordProtectedTransport]` +
    // `racComparison: "exact"`, i.e. every AuthnRequest would demand
    // exactly password-over-TLS. An IdP with an MFA sign-on policy can
    // answer that with `NoAuthnContext` instead of a login, so we
    // invert the default: send no RequestedAuthnContext unless the
    // operator explicitly configured the class refs their IdP honours.
    ...(config.requestedAuthnContext
      ? {
          disableRequestedAuthnContext: false,
          authnContext: [...config.requestedAuthnContext.classRefs],
          racComparison: config.requestedAuthnContext.comparison ?? "exact",
        }
      : { disableRequestedAuthnContext: true }),
    cacheProvider: methodScratchCacheProvider(
      binding.scratch,
      IN_RESPONSE_TO_TTL_MS,
    ),
    // O3: per-connection SP signing key (opt-in). node-saml signs the
    // HTTP-Redirect AuthnRequest / logout messages with this PEM keypair.
    ...(binding.signing
      ? {
          privateKey: binding.signing.privateKeyPem,
          publicCert: binding.signing.certPem,
          signatureAlgorithm: "sha256" as const,
        }
      : {}),
    // SP-emitted LogoutResponse / LogoutRequest destination (the IdP's
    // SLO endpoint). node-saml's logout URL builder reads `logoutUrl`.
    ...(binding.logoutUrl ? { logoutUrl: binding.logoutUrl } : {}),
    // Encrypted-assertion decryption (opt-in per connection).
    ...(binding.decryptionPvk ? { decryptionPvk: binding.decryptionPvk } : {}),
  })
}
