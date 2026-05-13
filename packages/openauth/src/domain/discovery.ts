/**
 * Metadata-document builders for `/.well-known/openid-configuration` and
 * `/.well-known/jwks.json`.
 *
 * Pure functions over typed ports + a small options record.
 */
import type { KeyStore } from "../ports/key-store"
import type { AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"

import { buildJwksDocument } from "./jwt"

export type DiscoveryDocument = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  revocation_endpoint: string
  introspection_endpoint: string
  /** OIDC RP-Initiated Logout 1.0 §2. */
  end_session_endpoint: string
  /** RFC 9126 §5. */
  pushed_authorization_request_endpoint: string
  /**
   * RFC 9126 §5. True iff every client on this tenant is required to use
   * PAR. We advertise `false` at the tenant level — the per-client toggle
   * is read at request time.
   */
  require_pushed_authorization_requests: boolean
  response_types_supported: string[]
  grant_types_supported: string[]
  subject_types_supported: string[]
  id_token_signing_alg_values_supported: string[]
  scopes_supported: string[]
  token_endpoint_auth_methods_supported: string[]
  code_challenge_methods_supported: string[]
}

export type DiscoveryDeps = {
  issuerUrl: string
  /** Override path defaults if mounted under a non-root prefix. */
  paths?: Partial<{
    authorize: string
    token: string
    userinfo: string
    jwks: string
    revoke: string
    introspect: string
    endSession: string
    par: string
  }>
  /** Advertised scopes. Defaults to `["openid", "email", "profile"]`. */
  scopes?: string[]
}

export function buildDiscoveryDocument(deps: DiscoveryDeps): DiscoveryDocument {
  const base = deps.issuerUrl.replace(/\/+$/, "")
  const p = deps.paths ?? {}
  return {
    issuer: deps.issuerUrl,
    authorization_endpoint: `${base}${p.authorize ?? "/authorize"}`,
    token_endpoint: `${base}${p.token ?? "/token"}`,
    userinfo_endpoint: `${base}${p.userinfo ?? "/userinfo"}`,
    jwks_uri: `${base}${p.jwks ?? "/.well-known/jwks.json"}`,
    revocation_endpoint: `${base}${p.revoke ?? "/revoke"}`,
    introspection_endpoint: `${base}${p.introspect ?? "/introspect"}`,
    end_session_endpoint: `${base}${p.endSession ?? "/end_session"}`,
    pushed_authorization_request_endpoint: `${base}${p.par ?? "/par"}`,
    require_pushed_authorization_requests: false,
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "client_credentials",
    ],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256", "EdDSA"],
    scopes_supported: deps.scopes ?? ["openid", "email", "profile"],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
      "none",
    ],
    code_challenge_methods_supported: ["S256"],
  }
}

export type JwksDoc = ReturnType<typeof buildJwksDocument>

export async function buildJwks(
  keyStore: KeyStore,
): Promise<Result<JwksDoc, AuthError>> {
  const res = await keyStore.signingKeys()
  if (isErr(res)) return err(res.error)
  return ok(buildJwksDocument(res.value))
}
