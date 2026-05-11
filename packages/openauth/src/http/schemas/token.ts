/**
 * Zod schemas for the `/token` endpoint.
 *
 * The endpoint accepts `application/x-www-form-urlencoded` per RFC 6749.
 * `grant_type` discriminates between the supported grants — currently
 * `authorization_code` and `refresh_token`. (`client_credentials` arrives in
 * Phase 5 with the m2m method.)
 */
import { z } from "zod"

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

export const tokenRequestSchema = z.discriminatedUnion("grant_type", [
  authorizationCodeGrantSchema,
  refreshTokenGrantSchema,
  clientCredentialsGrantSchema,
])

export type TokenRequest = z.infer<typeof tokenRequestSchema>
