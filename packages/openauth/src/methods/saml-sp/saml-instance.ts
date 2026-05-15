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
const NAME_ID_FORMAT_URN: Record<SamlNameIdFormat, string> = {
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
    // Security posture — strict by default. SP-initiated only for now;
    // unsolicited Responses require an outstanding InResponseTo.
    validateInResponseTo: ValidateInResponseTo.always,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    acceptedClockSkewMs: (config.clockSkewSeconds ?? 60) * 1000,
    cacheProvider: methodScratchCacheProvider(
      binding.scratch,
      IN_RESPONSE_TO_TTL_MS,
    ),
  })
}
