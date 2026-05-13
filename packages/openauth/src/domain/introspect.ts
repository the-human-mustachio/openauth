/**
 * `/introspect` endpoint logic (RFC 7662).
 *
 * RFC 7662 §2.1 REQUIRES authentication: "To prevent token scanning
 * attacks, the endpoint MUST also require some form of authorization to
 * access this endpoint." Confidential-client credentials are validated
 * against the **presenter's** tenant — resolved by the HTTP layer from
 * the request, exactly the same way `/token client_credentials` resolves
 * tenant. Authenticating before touching the token's `tid` means:
 *
 *   - Unknown presenting client OR wrong secret → `invalid_client`
 *     (uniform — the response says nothing about the token).
 *   - Token belongs to a different tenant than the presenter, or names a
 *     different client as audience, or fails verification → `{active: false}`.
 *
 * Pre-fix the order was "verify token → load token's tenant → look up
 * presenter in *that* tenant", which let a client authenticated in
 * tenant X probe whether its `client_id` existed in tenant Y by
 * watching for `invalid_client` versus `{active: false}` responses.
 *
 * Audience check (RFC 7662 §2.2): an authenticated client may only
 * inspect tokens that name it as the audience. Tokens belonging to a
 * different client return `{ active: false }` — never a structured
 * error — to avoid leaking which tokens exist.
 *
 * Refresh tokens are not introspectable here; RFC 7662 §2.1 only
 * requires access-token introspection, and our refresh tokens are
 * opaque and don't carry the standard introspection metadata.
 */
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { AuthError } from "../types/error"
import { authError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { AccessTokenClaims } from "../types/token"
import type { TenantId } from "../types/tenant"

import { verifyClientCredentials } from "./client-auth"
import { verifyAccessToken } from "./jwt"

export type IntrospectResponse =
  | { active: false }
  | {
      active: true
      sub: string
      aud: string
      iss: string
      exp: number
      iat: number
      scope?: string
      client_id?: string
      /** RFC 7662 §2.2 — the token's type indicator. */
      token_type: "Bearer" | "DPoP"
      tid: string
      mid?: string
      mkind?: string
      /** Library-specific — subject schema discriminator (e.g. "user", "admin"). */
      subject_type?: string
      /** RFC 9449 §6 — present when the access token is DPoP-bound. */
      cnf?: { jkt: string }
    }

export type IntrospectRequest = {
  token: string
  tokenTypeHint?: "access_token" | "refresh_token"
  /** REQUIRED — RFC 7662 §2.1. */
  clientId: string
  clientSecret?: string
  /**
   * The tenant the presenting client belongs to. Resolved by the HTTP
   * layer via `IdPOptions.resolveTenant`, just like for the m2m grant.
   * Cross-tenant introspection collapses to `{active: false}` regardless
   * of whether the presenter's client exists in the token's tenant.
   */
  presenterTenantId: TenantId
}

export type IntrospectDeps = {
  keyStore: KeyStore
  configStore: ConfigStore
  /** Expected issuer for additional validation. */
  issuerUrl?: string
}

export async function introspect(
  req: IntrospectRequest,
  deps: IntrospectDeps,
): Promise<Result<IntrospectResponse, AuthError>> {
  // 1. Authenticate the presenting client against its OWN tenant before
  //    looking at the token. Failure here = `invalid_client` (RFC 7662
  //    §2.1). The presenter's tenant is the only signal we trust until
  //    auth succeeds.
  const presenterTenantCfg = await deps.configStore.getTenantConfig(
    req.presenterTenantId,
  )
  if (isErr(presenterTenantCfg)) {
    return err(authError.invalidClient(`unknown client "${req.clientId}"`))
  }
  const presenter = presenterTenantCfg.value.clients.find(
    (c) => c.id === req.clientId,
  )
  if (!presenter) {
    return err(authError.invalidClient(`unknown client "${req.clientId}"`))
  }
  const authErr = await verifyClientCredentials(presenter, req.clientSecret)
  if (authErr) return err(authErr)

  // 2. Try to verify the token. Unverifiable / wrong issuer / expired →
  //    `{active: false}` so a presenter cannot tell the difference
  //    between a forged token and a valid one belonging to another
  //    tenant or client.
  const keysRes = await deps.keyStore.signingKeys()
  if (isErr(keysRes)) return err(keysRes.error)
  let claims: AccessTokenClaims | null
  try {
    claims = await verifyAccessToken(req.token, keysRes.value, {
      ...(deps.issuerUrl ? { issuer: deps.issuerUrl } : {}),
    })
  } catch {
    return ok({ active: false })
  }

  // 3. Token's tenant must match the presenter's tenant. RFC 7662 lets
  //    us return `{active: false}` here — never a structured error —
  //    so a presenter can't probe across tenants. (H6 of the
  //    post-rebuild review.)
  if ((claims.tid as TenantId) !== req.presenterTenantId) {
    return ok({ active: false })
  }

  // 4. Audience check (RFC 7662 §2.2): only the client the token names
  //    as audience may see its claims.
  if (claims.aud !== req.clientId) {
    return ok({ active: false })
  }

  const subjectType = (claims.claim as { type?: string } | undefined)?.type
  return ok({
    active: true,
    sub: claims.sub,
    aud: claims.aud,
    iss: claims.iss,
    exp: claims.exp,
    iat: claims.iat,
    scope: claims.scope,
    client_id: claims.aud,
    token_type: claims.cnf?.jkt !== undefined ? "DPoP" : "Bearer",
    tid: claims.tid,
    mid: claims.mid,
    mkind: claims.mkind,
    ...(subjectType !== undefined ? { subject_type: subjectType } : {}),
    ...(claims.cnf !== undefined ? { cnf: claims.cnf } : {}),
  })
}
