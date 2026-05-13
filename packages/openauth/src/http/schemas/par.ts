/**
 * Zod schema for the `POST /par` body (RFC 9126 §2).
 *
 * The shape is identical to `/authorize` query parameters; we just need
 * `client_id` to identify the authenticating client. `client_secret` is
 * accepted in-body for `client_secret_post` auth.
 */
import { z } from "zod"

export const parBodySchema = z
  .object({
    client_id: z
      .string({ required_error: "missing client_id" })
      .min(1, "empty client_id"),
    client_secret: z.string().optional(),
  })
  // `.catchall(z.string())` validates AND types passthrough keys as
  // strings — `application/x-www-form-urlencoded` values are always
  // strings at the wire level, so this also rejects malformed bodies
  // where a key somehow carries a non-string value.
  .catchall(z.string())

export type ParBody = z.infer<typeof parBodySchema>
