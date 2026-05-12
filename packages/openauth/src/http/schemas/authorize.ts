/**
 * Zod schemas for the `/authorize` endpoint.
 *
 * Parse the raw query into an `AuthorizationRequest` shape. We surface OAuth
 * `invalid_request` (or the more specific `unsupported_response_type` /
 * `invalid_scope`) for any structural failure here; downstream domain code
 * then handles semantic validation (client lookup, redirect-uri match, PKCE
 * requirement, etc.).
 */
import { z } from "zod"

/** RFC 6749 scope-token regex (visible ASCII minus delimiters). */
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/

const csv = z
  .string()
  .min(1)
  .transform((s) =>
    s
      .split(/\s+/)
      .map((part) => part.trim())
      .filter((part) => part.length > 0),
  )

const scopeParam = z
  .string()
  .transform((s) =>
    s
      .split(/\s+/)
      .map((part) => part.trim())
      .filter((part) => part.length > 0),
  )
  .pipe(z.array(z.string().regex(SCOPE_TOKEN, "invalid scope token")))

export const authorizeQuerySchema = z
  .object({
    response_type: z.string({
      required_error: "missing response_type",
    }),
    client_id: z
      .string({ required_error: "missing client_id" })
      .min(1, "empty client_id"),
    redirect_uri: z
      .string({ required_error: "missing redirect_uri" })
      .url("redirect_uri must be a valid URL"),
    scope: scopeParam.optional(),
    state: z.string().optional(),
    audience: z.string().optional(),
    method_id: z.string().optional(),
    code_challenge: z.string().optional(),
    code_challenge_method: z.literal("S256").optional(),
    prompt: csv.optional(),
    ui_locales: csv.optional(),
    nonce: z.string().optional(),
  })
  .passthrough()

export type AuthorizeQuery = z.infer<typeof authorizeQuerySchema>
