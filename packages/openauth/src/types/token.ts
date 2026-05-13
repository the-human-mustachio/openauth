/**
 * Token-domain shapes — auth code payload (snapshot of `FlowRecord` at
 * handoff), access-token claims, refresh-token payload, and the small
 * envelopes the `TokenStore` persists.
 *
 * Per AD9, access tokens are JWTs (ES256 by default, Ed25519 optional per
 * AD11) and refresh tokens are opaque server-side records.
 */
import type { SubjectClaim } from "./subject"
import type { TenantId } from "./tenant"

/**
 * Payload stored under an auth code. Built at callback time from the consumed
 * `FlowRecord` plus the method's `success` result. Encrypted at rest by
 * `TokenStore.saveCode` (see `ports/CONSISTENCY.md`).
 *
 * `methodState` is intentionally **not** snapshotted: it served its
 * upstream-callback purpose and is dropped with the flow record.
 */
export type CodePayload = {
  tenantId: TenantId
  clientId: string
  appRedirectUri: string
  /** Relying party's `state` param, echoed back at success. */
  appState: string | null
  scopes: string[]
  audience?: string
  /** Relying-party → IdP PKCE; verified at `/token` against the RP's verifier. */
  clientPkce?: { challenge: string; method: "S256" }
  /** Tenant-local method instance id (`MethodConfig.id`). */
  methodId: string
  /** Factory kind (`MethodConfig.kind`). */
  methodKind: string
  /** User's `requestContext` snapshot, if any. */
  context?: Record<string, unknown> | null
  /** Upstream system's stable identifier (from `MethodResult.success`). */
  providerSubject: string
  /** Typed-per-method properties from `MethodResult.success`. */
  properties: unknown
  /**
   * Relying party's OIDC `nonce` (OIDC Core §3.1.2.1). Snapshotted from
   * `FlowRecord.appNonce`. Echoed into the issued `id_token` when present.
   */
  appNonce?: string
  /**
   * Seconds-since-epoch when end-user authentication completed
   * (OIDC Core §2 `auth_time`). Stamped at the moment the method's
   * `MethodResult.success` fires. Carried into the `id_token` and forward
   * across refresh-token rotations.
   */
  authTime: number
  /** Auth-code TTL is 60 s — framework refuses anything longer. */
  expiresAt: number
}

/**
 * OIDC Core §5.1 `address` claim. Structured object value rather than a
 * scalar — distinct from the rest of the profile fields.
 */
export type AddressClaim = {
  formatted?: string
  street_address?: string
  locality?: string
  region?: string
  postal_code?: string
  country?: string
}

/**
 * OIDC Core §5.1 profile / email / phone / address claims, gated by the
 * `profile` / `email` / `phone` / `address` scopes via §5.4. Reused by
 * `IdTokenClaims` and the `/userinfo` response so the two surfaces share
 * exactly one source of truth for scope→claim mapping.
 *
 * Every field is optional: presence depends on (a) which scopes were
 * granted and (b) whether the host populated the matching key in
 * `SubjectClaim.properties`.
 */
export type ScopedProfileClaims = {
  // `profile` scope
  name?: string
  given_name?: string
  family_name?: string
  middle_name?: string
  nickname?: string
  preferred_username?: string
  profile?: string
  picture?: string
  website?: string
  gender?: string
  birthdate?: string
  zoneinfo?: string
  locale?: string
  updated_at?: number
  // `email` scope
  email?: string
  email_verified?: boolean
  // `phone` scope
  phone_number?: string
  phone_number_verified?: boolean
  // `address` scope
  address?: AddressClaim
}

/**
 * OIDC `id_token` JWT claims this IdP issues at `/token` when `openid`
 * scope is granted (OIDC Core §2). Distinct from access-token claims:
 *
 *  - `aud` is the relying-party `client_id` (not the API audience).
 *  - `nonce` echoes the RP's `/authorize` `nonce` parameter when present.
 *  - `auth_time` is stable across refresh-token rotations (OIDC Core §12).
 *  - `at_hash` is recommended whenever an id_token and access_token are
 *    returned in the same response (§3.1.3.6).
 *
 * Standard OIDC claim names use snake_case on the wire; TypeScript field
 * names match to keep the marshalling 1:1.
 */
export type IdTokenClaims = ScopedProfileClaims & {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  /** Seconds-since-epoch when end-user auth completed. */
  auth_time?: number
  /** RP-supplied OIDC nonce, when present. MUST equal the `/authorize` value. */
  nonce?: string
  /** Authentication Methods References (RFC 8176). */
  amr?: string[]
  /** Authentication Context Class Reference. */
  acr?: string
  /** Authorized party — the client_id of the party the id_token is for. */
  azp?: string
  /** Access-token hash (OIDC Core §3.1.3.6). */
  at_hash?: string
}

/** Access-token JWT claims this IdP issues. */
export type AccessTokenClaims = {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  /** Tenant id. */
  tid: TenantId
  /** Tenant-local method instance id that originated this token. */
  mid?: string
  /** Factory kind that originated this token. */
  mkind?: string
  scope?: string
  /** DPoP confirmation claim (Phase 8). */
  cnf?: { jkt: string }
  /** The structured subject (matches `SubjectClaim`). Inlined for resource servers. */
  claim: SubjectClaim
}

/**
 * Opaque refresh-token payload — persisted in `TokenStore` with strong CAS
 * semantics (see `ports/CONSISTENCY.md`). The token itself is a random
 * string; the payload is what the store returns on consume.
 */
export type RefreshTokenPayload = {
  tenantId: TenantId
  clientId: string
  /** Stable subject id derived from the issued `SubjectClaim`. */
  subjectId: string
  claim: SubjectClaim
  scopes: string[]
  audience?: string
  /** Reuse-detection chain id. Rotation issues a new token with the same family. */
  family: string
  /**
   * Tenant-local method instance id (`MethodConfig.id`) that originated the
   * chain. Preserved across `refresh_token` rotations so descendant access
   * tokens carry the original `mid` / `mkind` claims instead of the
   * grant-type literal "refresh".
   */
  methodId: string
  /** Factory kind (`MethodConfig.kind`) that originated the chain. */
  methodKind: string
  /**
   * Seconds-since-epoch when end-user authentication originally completed
   * (OIDC Core §2 `auth_time`). Stable across refresh-token rotations —
   * `auth_time` does **not** advance on refresh, only on re-authentication.
   */
  authTime: number
  /**
   * RFC 7638 JWK thumbprint of the client's DPoP key (RFC 9449 §6.1).
   * Present when the original token grant was DPoP-bound. Refresh-grant
   * rotation REQUIRES a fresh DPoP proof whose thumbprint matches; absent
   * = the token is plain Bearer and Bearer is acceptable on refresh.
   */
  dpopJkt?: string
  /** Wall-clock issuance and absolute-expiry timestamps. */
  issuedAt: number
  expiresAt: number
}

/** Response body of `/token` (RFC 6749 §5.1). */
export type TokenResponse = {
  access_token: string
  token_type: "Bearer" | "DPoP"
  expires_in: number
  refresh_token?: string
  scope?: string
  id_token?: string
}
