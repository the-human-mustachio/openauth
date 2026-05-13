/**
 * Zod schema for `POST /register` (RFC 7591 §2).
 *
 * The body is `application/json`. We surface invalid structure as
 * `invalid_request` rather than the spec's `invalid_client_metadata` /
 * `invalid_redirect_uri` codes — the library collapses all wire-format
 * problems to the OAuth-2.0 `invalid_request` family for consistency.
 */
import { z } from "zod"

export const registerBodySchema = z
  .object({
    client_name: z.string().min(1).optional(),
    redirect_uris: z
      .array(z.string().url("redirect_uri must be a valid URL"))
      .min(1, "redirect_uris must be a non-empty array"),
    grant_types: z.array(z.string()).optional(),
    response_types: z.array(z.string()).optional(),
    token_endpoint_auth_method: z
      .enum(["none", "client_secret_basic", "client_secret_post"])
      .optional(),
    scope: z.string().optional(),
    post_logout_redirect_uris: z.array(z.string().url()).optional(),
    sector_identifier_uri: z.string().url().optional(),
    contacts: z.array(z.string()).optional(),
  })
  .passthrough()

export type RegisterBody = z.infer<typeof registerBodySchema>
