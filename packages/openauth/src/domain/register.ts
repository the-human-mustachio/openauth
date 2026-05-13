/**
 * Dynamic Client Registration (RFC 7591).
 *
 * The host owns persistence — this module validates the wire request,
 * mints a fresh `client_id` (and `client_secret` for confidential
 * clients), invokes the host's `registerClient` hook with a structured
 * `ClientConfig`, and builds the §3.2.1 response.
 *
 * Per RFC 7591:
 *  - §2: registration request body is JSON, fields include
 *    `client_name`, `redirect_uris`, `grant_types`, `response_types`,
 *    `token_endpoint_auth_method`, `scope`, etc.
 *  - §3.2.1: response is JSON with `client_id`, optional
 *    `client_secret`, `client_id_issued_at`, optional
 *    `client_secret_expires_at`, and the registered metadata.
 *  - §3.2.2: structural problems → `invalid_client_metadata` /
 *    `invalid_redirect_uri`. We collapse to `invalid_request` for
 *    consistency with the rest of the library's error mapping.
 */
import { authError, type AuthError } from "../types/error"
import type {
  RegisterClient,
  RegisterClientRequest,
  RegisterClientResponse,
} from "../types/idp"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantContext } from "../types/tenant"

import { randomId, randomToken } from "./crypto"
import { hashClientSecret } from "./token"

export type RegisterDeps = {
  registerClient?: RegisterClient
  clock: () => number
  /** Test override for deterministic client_id. */
  newClientId?: () => string
  /** Test override for deterministic client_secret. */
  newClientSecret?: () => string
}

export async function registerNewClient(
  request: RegisterClientRequest,
  tenant: TenantContext,
  deps: RegisterDeps,
): Promise<Result<RegisterClientResponse, AuthError>> {
  if (!deps.registerClient) {
    return err(
      authError.invalidRequest(
        "dynamic client registration is not enabled on this deployment",
      ),
    )
  }

  // RFC 7591 §2 — redirect_uris is REQUIRED for any client that uses a
  // redirect-based grant. We accept the field as required at the wire
  // level (schema enforces) and validate non-empty here.
  if (!Array.isArray(request.redirect_uris) || request.redirect_uris.length === 0) {
    return err(
      authError.invalidRequest(
        "redirect_uris must be a non-empty array",
        "redirect_uris",
      ),
    )
  }
  for (const uri of request.redirect_uris) {
    try {
      // Reject relative / opaque URIs eagerly so the host gets a clean
      // structural rejection instead of a runtime surprise at /authorize.
      // RFC 7591 §2 leaves URI scheme to grant-type semantics; we follow
      // the OAuth 2.1 BCP and require absolute URIs.
      void new URL(uri)
    } catch {
      return err(
        authError.invalidRequest(
          `redirect_uri "${uri}" is not a valid absolute URI`,
          "redirect_uris",
        ),
      )
    }
  }

  const authMethod = request.token_endpoint_auth_method ?? "client_secret_basic"
  const isPublic = authMethod === "none"
  const clientId = (deps.newClientId ?? randomId)()
  const grantTypes = request.grant_types ?? ["authorization_code"]
  const responseTypes = request.response_types ?? ["code"]
  const scopes = request.scope
    ? request.scope.split(/\s+/).filter(Boolean)
    : ["openid"]

  let secret: string | undefined
  let secretHash: string | undefined
  if (!isPublic) {
    secret = (deps.newClientSecret ?? randomToken)()
    secretHash = await hashClientSecret(secret)
  }

  const clientPartial = {
    id: clientId,
    name: request.client_name ?? clientId,
    redirectUris: request.redirect_uris,
    // Default scopes overlap with what the IdP advertises; hosts may
    // override during the hook call before persisting.
    scopes,
    grantTypes: grantTypes.filter((g): g is "authorization_code" | "refresh_token" | "client_credentials" =>
      g === "authorization_code" ||
      g === "refresh_token" ||
      g === "client_credentials",
    ),
    ...(request.post_logout_redirect_uris !== undefined
      ? { postLogoutRedirectUris: request.post_logout_redirect_uris }
      : {}),
    ...(request.sector_identifier_uri !== undefined
      ? { sectorIdentifier: request.sector_identifier_uri }
      : {}),
  }

  const clientConfig = isPublic
    ? {
        ...clientPartial,
        type: "public" as const,
        pkceRequired: true as const,
      }
    : {
        ...clientPartial,
        type: "confidential" as const,
        secretHash: secretHash!,
        pkceRequired: true,
      }

  const hookResult = await deps.registerClient({
    tenant,
    request,
  })
  // The hook may either:
  //  - persist `clientConfig` as-is (most common) and return it,
  //  - synthesize its own (host-owned id generation, custom scopes) and
  //    return that — in which case the secret we minted is moot.
  // We trust the hook's returned client + secret as authoritative.
  void clientConfig

  if (isErr(hookResult)) return err(hookResult.error)
  const persisted = hookResult.value.client
  const persistedSecret = hookResult.value.secret

  const issuedAt = Math.floor(deps.clock() / 1000)
  return ok({
    client_id: persisted.id,
    ...(persistedSecret !== undefined ? { client_secret: persistedSecret } : {}),
    client_id_issued_at: issuedAt,
    // RFC 7591 §3.2.1: `0` = no expiry.
    client_secret_expires_at: 0,
    redirect_uris: persisted.redirectUris,
    grant_types: persisted.grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: authMethod,
    ...(request.client_name !== undefined
      ? { client_name: request.client_name }
      : {}),
  })
}
