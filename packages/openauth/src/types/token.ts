/**
 * Token-domain shapes — auth code payload (snapshot of `FlowRecord` at
 * handoff), access-token claims, refresh-token payload, and the small
 * envelopes the `TokenStore` persists.
 *
 * Per AD9, access tokens are JWTs (ES256 by default, Ed25519 optional per
 * AD11) and refresh tokens are opaque server-side records.
 */
import type { SubjectClaim } from "./subject.js"
import type { TenantId } from "./tenant.js"

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
  /** Auth-code TTL is 60 s — framework refuses anything longer. */
  expiresAt: number
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
