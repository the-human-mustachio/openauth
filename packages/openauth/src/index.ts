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

// ─── New IdP public API (Phase 1+) ───

export type { Result } from "./types/result"
export { err, isErr, isOk, ok } from "./types/result"

export type { AuthError, AuthErrorCode } from "./types/error"
export { authError } from "./types/error"

export type {
  ClientConfig,
  ConfidentialClientConfig,
  GrantType,
  MethodConfig,
  MethodType,
  PublicClientConfig,
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

// Phase 4 — credential + WebAuthn method factories.
export { passwordMethod } from "./methods/password"
export type {
  PasswordMethodOptions,
  PasswordProperties,
  PasswordUser,
  PasswordUserStore,
  PasswordState,
} from "./methods/password"
export { codeMethod } from "./methods/code"
export type {
  CodeMethodOptions,
  CodeProperties,
  CodeState,
} from "./methods/code"
export { m2mMethod } from "./methods/m2m"
export type { M2MMethodOptions, M2MProperties } from "./methods/m2m"
export { passkeyMethod } from "./methods/passkey"
export type {
  PasskeyMethodOptions,
  PasskeyProperties,
  PasskeyState,
  PasskeyCredentialStore,
  StoredCredential,
} from "./methods/passkey"

export {
  argon2idHasher,
  DEFAULT_ARGON2ID_PARAMS,
} from "./domain/password-hash"
export type {
  PasswordHasher,
  Argon2idParams,
} from "./domain/password-hash"

// Phase 5 — OAuth / OIDC provider factories.
export { buildOauth2Method } from "./methods/oauth2-generic"
export type {
  Oauth2MethodInput,
  Oauth2Properties,
  Oauth2State,
} from "./methods/oauth2-generic"
export { buildOidcMethod } from "./methods/oidc-generic"
export type { OidcMethodInput } from "./methods/oidc-generic"

// Generic multi-tenant factories. Reach for these first when each
// tenant brings its own issuer / client credentials. The vendor
// factories above (googleFactory etc.) are convenience wrappers when
// the issuer is fixed.
export {
  oauth2Factory,
  oidcFactory,
  type Oauth2FactoryConfig,
  type OidcFactoryConfig,
} from "./methods/oauth2-factory"

export {
  appleFactory,
  cognitoFactory,
  discordFactory,
  facebookFactory,
  githubFactory,
  googleFactory,
  jumpcloudFactory,
  keycloakFactory,
  linkedinFactory,
  microsoftFactory,
  slackFactory,
  spotifyFactory,
  twitchFactory,
  xFactory,
  yahooFactory,
} from "./methods/providers"

import type { IdP, IdPOptions } from "./types/idp"
import { MethodCache } from "./domain/method-cache"
import { buildRouter } from "./http/router"
import type { HttpDeps } from "./http/context"

/**
 * Construct a new IdP from the supplied options.
 *
 * Phase 3 ships the full HTTP surface backed by the Phase 2 domain
 * functions. Wire up:
 *
 *  - A `MethodCache` over the configured factories. The factory map's
 *    keys MUST equal each factory's `kind`; we throw on construction if
 *    any disagree.
 *  - A `HttpDeps` record passed into the Hono router.
 *  - The returned `IdP.handle` is `app.fetch.bind(app)`; the per-endpoint
 *    primitives (`authorize`, `token`, etc.) re-enter the same app.
 */
export function createIdP(opts: IdPOptions): IdP {
  // Validate factory-key invariant before any request can hit a bad map.
  const mismatched = Object.entries(opts.methods)
    .filter(([key, factory]) => key !== factory.kind)
    .map(([key, factory]) => `${key}!=${factory.kind}`)
  if (mismatched.length > 0) {
    throw new Error(
      `createIdP: methods map keys must equal factory.kind. Offenders: ${mismatched.join(", ")}`,
    )
  }

  const clock = () => Date.now()
  const auditLog = opts.auditLog
  const methodCache = new MethodCache({
    factories: opts.methods,
    ...(auditLog ? { auditLog } : {}),
    now: clock,
  })

  const resolveIssuer = (req: Request): string =>
    typeof opts.issuerUrl === "string" ? opts.issuerUrl : opts.issuerUrl(req)

  const deps: HttpDeps = {
    configStore: opts.configStore,
    tokenStore: opts.tokenStore,
    sessionStore: opts.sessionStore,
    keyStore: opts.keyStore,
    ...(opts.methodStore ? { methodStore: opts.methodStore } : {}),
    ...(auditLog ? { auditLog } : {}),
    methodCache,
    stateKeys: opts.stateKeys,
    resolveIssuer,
    ...(opts.callbackHostFor ? { callbackHostFor: opts.callbackHostFor } : {}),
    resolveTenant: opts.resolveTenant,
    success: opts.success,
    ...(opts.persistUpstreamTokens
      ? { persistUpstreamTokens: opts.persistUpstreamTokens }
      : {}),
    clock,
    cookieDefaults: { secure: true },
  }

  const app = buildRouter(deps)
  const fetch = async (req: Request): Promise<Response> =>
    await app.fetch(req)

  return {
    handle: fetch,
    authorize: fetch,
    token: fetch,
    userinfo: fetch,
    jwks: fetch,
    discovery: fetch,
    revoke: fetch,
    introspect: fetch,
  }
}
