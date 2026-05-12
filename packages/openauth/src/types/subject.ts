/**
 * Subject — the typed principal the IdP issues at the end of an auth flow.
 *
 * Per AD4 / plan §"Subject", Zod is the canonical schema library. The
 * subject schema type is library-agnostic at the boundary (any schema that
 * implements the [Standard Schema v1] spec — including Zod 3.24+, Valibot,
 * and Arktype) so existing consumers can migrate from Valibot/Arktype
 * without rewriting subject definitions.
 *
 * [Standard Schema v1]: https://github.com/standard-schema/standard-schema
 */
import type { v1 } from "@standard-schema/spec"

/**
 * Map of subject-type id → schema for that subject's `properties`.
 *
 * @example
 * ```ts
 * import { z } from "zod"
 *
 * const subjects: SubjectSchema = {
 *   user:  z.object({ userId: z.string(), email: z.string().email() }),
 *   admin: z.object({ adminId: z.string(), roles: z.array(z.string()) }),
 * }
 * ```
 */
export type SubjectSchema = Record<string, v1.StandardSchema>

/**
 * Helper that infers the discriminated-union `{ type, properties }` shape
 * from a `SubjectSchema`. Used to type the IdP's `success` callback return
 * and the access-token `claim` payload.
 */
export type SubjectPayload<T extends SubjectSchema> = {
  [type in keyof T & string]: {
    type: type
    properties: v1.InferOutput<T[type]>
  }
}[keyof T & string]

/**
 * Generic typed-subject claim — what the user's `IdPOptions.success`
 * callback returns and what is inlined as `claim` on the access token.
 *
 * Domain / port signatures keep the generic open (`SubjectClaim`) so the
 * framework doesn't need to know each consumer's subject schema. Concrete
 * call sites narrow `T extends SubjectSchema` for type safety.
 */
export type SubjectClaim<T extends SubjectSchema = SubjectSchema> =
  SubjectPayload<T>
