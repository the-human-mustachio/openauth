/**
 * `/introspect` endpoint logic (RFC 7662).
 *
 * RFC 7662 §2.1 REQUIRES authentication: "To prevent token scanning
 * attacks, the endpoint MUST also require some form of authorization to
 * access this endpoint." Confidential-client credentials are validated
 * against the tenant the token belongs to.
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
      tid: string
      mid?: string
      mkind?: string
    }

export type IntrospectRequest = {
  token: string
  tokenTypeHint?: "access_token" | "refresh_token"
  /** REQUIRED — RFC 7662 §2.1. */
  clientId: string
  clientSecret?: string
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
  const keysRes = await deps.keyStore.signingKeys()
  if (isErr(keysRes)) return err(keysRes.error)

  // Try to verify the token. If it fails — bad signature, expired,
  // wrong issuer — we still need to acknowledge the caller authenticated
  // before returning `{active: false}`. Without a verified `tid` we
  // can't look up the calling client, so we treat unverifiable tokens
  // as inactive and return without consulting the tenant.
  let claims: AccessTokenClaims | null
  try {
    claims = await verifyAccessToken(req.token, keysRes.value, {
      ...(deps.issuerUrl ? { issuer: deps.issuerUrl } : {}),
    })
  } catch {
    return ok({ active: false })
  }

  const tenantCfg = await deps.configStore.getTenantConfig(
    claims.tid as TenantId,
  )
  if (isErr(tenantCfg)) {
    return ok({ active: false })
  }
  const client = tenantCfg.value.clients.find((c) => c.id === req.clientId)
  if (!client) {
    return err(authError.invalidClient(`unknown client "${req.clientId}"`))
  }
  const authErr = await verifyClientCredentials(client, req.clientSecret)
  if (authErr) return err(authErr)

  // RFC 7662 §2.2 — only the client a token names as audience may see
  // its claims. Cross-client introspection returns {active: false}
  // rather than leaking that the token exists.
  if (claims.aud !== req.clientId) {
    return ok({ active: false })
  }

  return ok({
    active: true,
    sub: claims.sub,
    aud: claims.aud,
    iss: claims.iss,
    exp: claims.exp,
    iat: claims.iat,
    scope: claims.scope,
    client_id: claims.aud,
    tid: claims.tid,
    mid: claims.mid,
    mkind: claims.mkind,
  })
}
