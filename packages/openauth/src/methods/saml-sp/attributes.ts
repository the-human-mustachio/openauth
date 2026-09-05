/**
 * Attribute mapping — translate a node-saml `Profile` (already
 * cryptographically verified by the time it reaches here) into our
 * `SamlSpProperties`.
 *
 * node-saml flattens the assertion's `AttributeStatement` onto the
 * `Profile` object as arbitrary top-level keys (single value → string,
 * multi-valued → array), plus the structural `nameID` /
 * `nameIDFormat` / `sessionIndex`. The host's `success` callback owns
 * the final `SubjectClaim`; this layer just normalises the SAML side
 * per the tenant's configured `SamlAttributeMapping`.
 *
 * Pure: no node-saml import, no I/O. `Profile` is modelled here as the
 * minimal structural shape we read, so this file stays free of the
 * third-party type (the public-API leak guard depends on that).
 */
import type {
  SamlAttributeMapping,
  SamlAttributeRef,
  SamlNameIdFormat,
  SamlSpProperties,
} from "./types"

/** The slice of node-saml's `Profile` we actually consume. */
export type VerifiedProfile = {
  nameID: string
  nameIDFormat: string
  sessionIndex?: string
  attributes: Record<string, unknown>
  /** `AuthnStatement/@AuthnInstant`, raw XSD dateTime. */
  authnInstant?: string
  /** `AuthnStatement/@SessionNotOnOrAfter`, already parsed to Unix ms. */
  sessionNotOnOrAfter?: number
  /** `AuthnContext/AuthnContextClassRef` — what the IdP actually asserted. */
  authnContextClassRef?: string
  responseXml: string
}

const NAME_ID_FORMAT_BY_URN: Record<string, SamlNameIdFormat> = {
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent": "persistent",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient": "transient",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": "emailAddress",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified": "unspecified",
}

function normalizeNameIdFormat(urn: string): SamlNameIdFormat {
  return NAME_ID_FORMAT_BY_URN[urn] ?? "unspecified"
}

/** First value if array, the value if scalar, else undefined. */
function scalar(v: unknown): string | undefined {
  if (typeof v === "string") return v
  if (Array.isArray(v) && v.length > 0 && typeof v[0] === "string") {
    return v[0]
  }
  return undefined
}

/** Preserve array shape for multi-valued attributes (e.g. groups). */
function multi(v: unknown): string | string[] | undefined {
  if (typeof v === "string") return v
  if (Array.isArray(v)) {
    const strs = v.filter((x): x is string => typeof x === "string")
    return strs.length > 0 ? strs : undefined
  }
  return undefined
}

function resolveRef(
  ref: SamlAttributeRef,
  profile: VerifiedProfile,
): string | string[] | undefined {
  if (ref.source === "nameId") return profile.nameID
  return multi(profile.attributes[ref.name])
}

export type MappedSubject = {
  providerSubject: string
  properties: SamlSpProperties
}

/**
 * Build `(providerSubject, properties)` from a verified profile.
 * Returns a string describing the failure when the configured subject
 * source resolves to nothing — the caller turns that into a `denied`
 * result rather than minting a subject-less success.
 */
export function mapProfile(
  profile: VerifiedProfile,
  mapping: SamlAttributeMapping,
): MappedSubject | { error: string } {
  const subjectRef: SamlAttributeRef = mapping.subject ?? { source: "nameId" }
  const subjectVal = scalar(resolveRef(subjectRef, profile))
  if (!subjectVal) {
    return {
      error:
        subjectRef.source === "nameId"
          ? "assertion NameID is empty; cannot derive subject"
          : `subject attribute "${subjectRef.name}" missing from assertion`,
    }
  }

  const attributes: Record<string, string | string[]> = {}

  const put = (key: string, ref: SamlAttributeRef | undefined): void => {
    if (!ref) return
    const v = resolveRef(ref, profile)
    if (v !== undefined) attributes[key] = v
  }

  put("email", mapping.email)
  put("name", mapping.name)
  put("groups", mapping.groups)
  if (mapping.emailVerified) {
    attributes["emailVerified"] = mapping.emailVerified.value ? "true" : "false"
  }
  for (const [key, ref] of Object.entries(mapping.custom ?? {})) {
    put(key, ref)
  }

  const authnInstant = profile.authnInstant
    ? Date.parse(profile.authnInstant)
    : Date.now()

  return {
    providerSubject: subjectVal,
    properties: {
      nameId: {
        value: profile.nameID,
        format: normalizeNameIdFormat(profile.nameIDFormat),
      },
      attributes,
      ...(profile.sessionIndex !== undefined
        ? { sessionIndex: profile.sessionIndex }
        : {}),
      authnInstant: Number.isNaN(authnInstant) ? Date.now() : authnInstant,
      ...(profile.sessionNotOnOrAfter !== undefined
        ? { sessionNotOnOrAfter: profile.sessionNotOnOrAfter }
        : {}),
      ...(profile.authnContextClassRef !== undefined
        ? { authnContextClassRef: profile.authnContextClassRef }
        : {}),
      raw: { responseXml: profile.responseXml },
    },
  }
}
