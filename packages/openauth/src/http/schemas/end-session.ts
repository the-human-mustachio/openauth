/**
 * Zod schema for `/end_session` (OIDC RP-Initiated Logout 1.0 §2).
 *
 * Every parameter is optional per spec. The domain layer enforces the
 * "needs identifying client to honor post_logout_redirect_uri" rule.
 */
import { z } from "zod"

export const endSessionParamsSchema = z
  .object({
    id_token_hint: z.string().optional(),
    client_id: z.string().min(1).optional(),
    post_logout_redirect_uri: z
      .string()
      .url("post_logout_redirect_uri must be a valid URL")
      .optional(),
    state: z.string().optional(),
    logout_hint: z.string().optional(),
    ui_locales: z.string().optional(),
  })
  .passthrough()

export type EndSessionParams = z.infer<typeof endSessionParamsSchema>
