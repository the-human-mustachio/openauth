/**
 * Zod schemas for RFC 7009 `/revoke` and RFC 7662 `/introspect`. Both are
 * advertised in discovery from Phase 3 onward; their HTTP shims live here so
 * the domain functions are reachable without waiting for Phase 8.
 */
import { z } from "zod"

export const revokeBodySchema = z.object({
  token: z.string().min(1, "missing token"),
  token_type_hint: z.enum(["access_token", "refresh_token"]).optional(),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
})

export const introspectBodySchema = z.object({
  token: z.string().min(1, "missing token"),
  token_type_hint: z.enum(["access_token", "refresh_token"]).optional(),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
})

export type RevokeBody = z.infer<typeof revokeBodySchema>
export type IntrospectBody = z.infer<typeof introspectBodySchema>
