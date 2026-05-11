/**
 * `@_mustachio/openauth` — public entry point.
 *
 * During the in-place rebuild (per AD12 in
 * `docs/plans/claude/idp-rebuild-plan.md`), the legacy `issuer` /
 * `createClient` / `createSubjects` exports remain available so existing
 * consumers continue to compile against `master`. The new `createIdP`
 * API and supporting types ship alongside; once Phases 2–5 land they
 * become the recommended path and the legacy entry points are removed.
 */

// ─── Legacy exports (deprecated; kept until Phase 5 ports the providers) ───

export {
  /**
   * @deprecated
   * Use `import { createClient } from "@openauthjs/openauth/client"` instead - it will tree shake better
   */
  createClient,
} from "./client"

export {
  /**
   * @deprecated
   * Use `import { createSubjects } from "@openauthjs/openauth/subject"` instead - it will tree shake better
   */
  createSubjects,
} from "./subject"

import { issuer } from "./issuer"

export {
  /**
   * @deprecated
   * Use `import { issuer } from "@openauthjs/openauth"` instead, it was renamed
   */
  issuer as authorizer,
  issuer,
}

// ─── New IdP public API (Phase 1 — types + stub) ───

export type { Result } from "./types/result"
export { err, isErr, isOk, ok } from "./types/result"

export type { AuthError, AuthErrorCode } from "./types/error"
export { authError } from "./types/error"

export type {
  ClientConfig,
  GrantType,
  MethodConfig,
  MethodType,
  StateEnvelope,
  StateKey,
  StateKeyRing,
  TenantConfig,
  TenantContext,
  TenantId,
  TenantRecovery,
  ThemeConfig,
} from "./types/tenant"
export { asTenantId } from "./types/tenant"

export type { FlowRecord } from "./types/flow"

export type {
  AuthMethod,
  AuthMethodFactory,
  CachePolicy,
  ClientFn,
  MethodContext,
  MethodDispatchData,
  MethodHandler,
  MethodResult,
  SetCookie,
} from "./types/method"

export type {
  AuthorizationRequest,
  AuthorizationState,
} from "./types/authorization"

export type {
  AccessTokenClaims,
  CodePayload,
  RefreshTokenPayload,
  TokenResponse,
} from "./types/token"

export type {
  SubjectClaim,
  SubjectPayload,
  SubjectSchema,
} from "./types/subject"

export type {
  FailureEvent,
  IdP,
  IdPOptions,
  PersistUpstreamTokens,
  SuccessEvent,
  SuccessMapInput,
} from "./types/idp"

export type { AuditEvent, AuditLog } from "./ports/audit-log"
export type { ConfigStore } from "./ports/config-store"
export type { EncryptionKey, KeyStore, SigningKey } from "./ports/key-store"
export type { MethodStore } from "./ports/method-store"
export type { SessionRecord, SessionStore } from "./ports/session-store"
export type { TokenStore } from "./ports/token-store"

import type { IdP, IdPOptions } from "./types/idp"

/**
 * Construct a new IdP from the supplied options. **Stub — Phase 1 ships
 * types only.** The full implementation lands in Phases 2 (domain
 * functions + memory adapters) and 3 (HTTP adapter).
 *
 * Calling this in Phase 1 throws `Error("createIdP: not implemented
 * (Phase 1 ships types only)")`. The function signature is the
 * committed public surface; downstream code can be type-checked against
 * it today.
 */
export function createIdP(_opts: IdPOptions): IdP {
  throw new Error("createIdP: not implemented (Phase 1 ships types only)")
}
