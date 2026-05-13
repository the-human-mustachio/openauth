/**
 * `id_token` assembly — claim selection, scope gating, `at_hash`, `amr`
 * derivation.
 *
 * OIDC Core §2 mandates `iss`, `sub`, `aud`, `exp`, `iat`. `auth_time` is
 * required when `max_age` was requested or `auth_time` is essential; we
 * always include it because we always know it (stamped at `success`).
 * `nonce` is required to echo the RP's `/authorize` value when present.
 *
 * Scope→claim mapping follows OIDC Core §5.4 exactly. Properties are
 * sourced from `SubjectClaim.properties` — hosts populate that record in
 * their `IdPOptions.success` callback. We only emit a profile claim
 * when (a) the corresponding scope was granted and (b) the value is a
 * recognized JSON-serializable type. Unknown values are silently
 * dropped (forward compat with subject schemas the host adds later).
 *
 * `at_hash` is computed per §3.1.3.6: left-half SHA-256 of the access
 * token's ASCII octets, base64url-encoded with no padding.
 *
 * `amr` (RFC 8176) is derived from `methodKind` via a small fixed table.
 * Methods that aren't in the table simply omit the claim — `amr` is
 * optional. Hosts that want richer amr semantics should add the claim
 * via the host claim hook (Phase E).
 */
import { base64url, sha256, utf8 } from "./crypto"
import type { ClaimsRequest } from "../types/authorization"
import type { IdTokenClaims, ScopedProfileClaims } from "../types/token"
import type { SubjectClaim } from "../types/subject"

/**
 * Map of OIDC scope name → list of profile claim names that scope grants
 * (OIDC Core §5.4). `openid` itself is the discriminator that an id_token
 * should be issued at all — it grants no profile claims.
 */
const SCOPE_TO_CLAIMS: Record<string, ReadonlyArray<string>> = {
  profile: [
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
  ],
  email: ["email", "email_verified"],
  phone: ["phone_number", "phone_number_verified"],
  address: ["address"],
}

/**
 * Derive `amr` from the originating `methodKind`. Values are RFC 8176
 * registered AMR codes. Returns `undefined` when no clean mapping exists
 * — `amr` is an OPTIONAL id_token claim, so omission is spec-compliant.
 */
export function deriveAmr(methodKind: string): string[] | undefined {
  switch (methodKind) {
    case "password":
      return ["pwd"]
    case "code":
      return ["otp"]
    case "passkey":
      // Resident credentials backed by a platform authenticator. Best
      // approximated by `hwk` (hardware key) per RFC 8176; platform
      // authenticators are usually hardware-backed (Secure Enclave,
      // TPM, etc.) even when the key is software-resident on disk.
      return ["hwk"]
    default:
      // External federated providers (google, github, oidc-generic, …)
      // — no standardized AMR for "logged in elsewhere", so omit.
      return undefined
  }
}

/**
 * `at_hash` per OIDC Core §3.1.3.6: left-half of SHA-256(access_token
 * ASCII), base64url. Always 16 bytes → 22 base64url characters for
 * SHA-256 (256-bit → 128-bit half → 16 bytes → 22 chars).
 */
export async function computeAtHash(accessToken: string): Promise<string> {
  const digest = await sha256(utf8.encode(accessToken))
  const half = digest.slice(0, digest.byteLength / 2)
  return base64url.encode(half)
}

/**
 * Filter a `SubjectClaim.properties` record down to claims granted by the
 * requested OIDC scopes, then optionally augment with claim names the RP
 * specifically requested via the OIDC Core §5.5 `claims` parameter.
 * Returns a typed `ScopedProfileClaims` ready to spread into the id_token
 * or `/userinfo` response. Properties not named by any granted scope or
 * explicit claim request are dropped.
 *
 * `extra` is the set of claim names the RP requested via `claims`
 * parameter for THIS surface (id_token vs userinfo). Listing a name in
 * `extra` bypasses scope gating per §5.5 ("works without the requestor
 * having to include the scope value").
 *
 * `customMappings` is a host-supplied scope → claim-names map merged on
 * top of the OIDC Core §5.4 table. Lets the host expose vendor-specific
 * identity fields (e.g. `tenant_id`, `org_role`) via a custom scope
 * (`scope=foo` granting `[tenant_id, …]`). Reserved §5.4 names cannot be
 * shadowed — the standard mapping always wins on collision so an
 * `email` scope can't accidentally start meaning something else.
 *
 * Host-supplied values are trusted to match their declared OIDC types
 * — schemas live on `IdPOptions.subjects`, not here. The narrowing cast
 * is the boundary between "host's responsibility" and "framework's
 * responsibility."
 */
export function pickScopedClaims(
  claim: SubjectClaim,
  scopes: ReadonlyArray<string>,
  extra: ReadonlyArray<string> = [],
  customMappings: Record<string, ReadonlyArray<string>> = {},
): ScopedProfileClaims {
  const props = (claim as { properties: Record<string, unknown> }).properties
  if (!props || typeof props !== "object") return {}
  // Standard §5.4 names take precedence: spread custom first, then
  // SCOPE_TO_CLAIMS, so a host can't override `email → [email, ...]`.
  const mappings: Record<string, ReadonlyArray<string>> = {
    ...customMappings,
    ...SCOPE_TO_CLAIMS,
  }
  const granted = new Set<string>()
  for (const scope of scopes) {
    const list = mappings[scope]
    if (!list) continue
    for (const c of list) granted.add(c)
  }
  for (const name of extra) granted.add(name)
  const out: Record<string, unknown> = {}
  for (const key of granted) {
    if (key in props && props[key] !== undefined) out[key] = props[key]
  }
  return out as ScopedProfileClaims
}

export type BuildIdTokenInput = {
  issuerUrl: string
  /** RP `client_id` — the id_token's `aud`. */
  audience: string
  /** Stable subject identifier (same value as the access token's `sub`). */
  subjectId: string
  claim: SubjectClaim
  scopes: ReadonlyArray<string>
  /** Seconds-since-epoch the user authenticated. */
  authTime: number
  /** RP-supplied OIDC nonce, when present. */
  appNonce?: string
  /** Wall clock (ms). */
  now: number
  /** id_token TTL (ms). Default 5 minutes. */
  ttlMs?: number
  /** Method kind for `amr` derivation. */
  methodKind: string
  /** Pre-signed access token whose `at_hash` is bound into the id_token. */
  accessToken: string
  /** OIDC Core §5.5 — RP-requested claims (this drives only id_token here). */
  claimsRequest?: ClaimsRequest
  /**
   * Host-supplied vendor scope → claim-names map. Merged on top of OIDC
   * Core §5.4 at scope-gating time. See `pickScopedClaims`.
   */
  customScopeClaims?: Record<string, ReadonlyArray<string>>
}

export const DEFAULT_ID_TOKEN_TTL_MS = 5 * 60 * 1000

/**
 * Assemble an `IdTokenClaims` object. Pure — no crypto except `at_hash`.
 * Caller signs the result via `signIdToken`.
 *
 * Composition is via spread so the type stays narrow: the base claim set
 * (REQUIRED OIDC §2 + auth_time + at_hash + optional nonce/amr) is built
 * first; the scope-gated §5.1 profile claims merge over the top via
 * `...pickScopedClaims(...)`. No dynamic index assignment, no cast.
 */
export async function buildIdTokenClaims(
  input: BuildIdTokenInput,
): Promise<IdTokenClaims> {
  const ttl = input.ttlMs ?? DEFAULT_ID_TOKEN_TTL_MS
  const amr = deriveAmr(input.methodKind)
  const extraClaims = Object.keys(input.claimsRequest?.id_token ?? {})
  return {
    iss: input.issuerUrl,
    sub: input.subjectId,
    aud: input.audience,
    exp: Math.floor((input.now + ttl) / 1000),
    iat: Math.floor(input.now / 1000),
    auth_time: input.authTime,
    at_hash: await computeAtHash(input.accessToken),
    ...(input.appNonce !== undefined ? { nonce: input.appNonce } : {}),
    ...(amr ? { amr } : {}),
    ...pickScopedClaims(
      input.claim,
      input.scopes,
      extraClaims,
      input.customScopeClaims ?? {},
    ),
  }
}

/** Predicate: does this token request warrant an `id_token` being issued? */
export function shouldIssueIdToken(scopes: ReadonlyArray<string>): boolean {
  return scopes.includes("openid")
}
