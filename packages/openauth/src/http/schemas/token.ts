/**
 * Zod schemas for the `/token` endpoint.
 *
 * The endpoint accepts `application/x-www-form-urlencoded` per RFC 6749.
 * `grant_type` discriminates between the supported grants:
 *   - `authorization_code`
 *   - `refresh_token`
 *   - `client_credentials`
 *   - `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)
 */
import { z } from "zod"

/** RFC 8693 §3 token-type identifiers used at this endpoint. */
export const TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange" as const
export const ACCESS_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:access_token" as const
export const REFRESH_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:refresh_token" as const

export const authorizationCodeGrantSchema = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(1, "missing code"),
  redirect_uri: z.string().url("invalid redirect_uri"),
  client_id: z.string().min(1, "missing client_id"),
  client_secret: z.string().optional(),
  code_verifier: z.string().optional(),
})

export const refreshTokenGrantSchema = z.object({
  grant_type: z.literal("refresh_token"),
  refresh_token: z.string().min(1, "missing refresh_token"),
  scope: z.string().optional(),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
})

export const clientCredentialsGrantSchema = z
  .object({
    grant_type: z.literal("client_credentials"),
    client_id: z.string().min(1, "missing client_id"),
    client_secret: z.string().min(1, "missing client_secret"),
    scope: z.string().optional(),
    audience: z.string().optional(),
    resource: z.string().optional(),
  })
  .passthrough()

/**
 * RFC 8693 §2.1 token-exchange request.
 *
 * `subject_token_type` MUST identify the type of `subject_token`. We only
 * accept access tokens here — refresh-token-as-subject is out of scope.
 *
 * `audience` is opaque to the library; the host's `exchangeAudience`
 * hook decides what counts as a legal target. In our two-level
 * `App × App-Tenant` encoding pattern this is the new `TenantId`.
 *
 * `actor_token` (delegation) is intentionally rejected at the handler;
 * only impersonation / audience-switching is supported in this phase.
 */
export const tokenExchangeGrantSchema = z
  .object({
    grant_type: z.literal(TOKEN_EXCHANGE_GRANT_TYPE),
    subject_token: z.string().min(1, "missing subject_token"),
    subject_token_type: z.literal(ACCESS_TOKEN_TYPE),
    audience: z.string().min(1, "missing audience"),
    requested_token_type: z.literal(ACCESS_TOKEN_TYPE).optional(),
    scope: z.string().optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
    actor_token: z.string().optional(),
    actor_token_type: z.string().optional(),
    resource: z.string().optional(),
  })
  .passthrough()

export const tokenRequestSchema = z.discriminatedUnion("grant_type", [
  authorizationCodeGrantSchema,
  refreshTokenGrantSchema,
  clientCredentialsGrantSchema,
  tokenExchangeGrantSchema,
])

export type TokenRequest = z.infer<typeof tokenRequestSchema>
