/**
 * Subject-claim validation at issuance.
 *
 * `IdPOptions.subjects` is a required option, and until 0.14.0 nothing on
 * the server read it: `createIdP` accepted the schema and signed whatever
 * `success()` returned. Two things went wrong as a result.
 *
 * First, the failure surfaced in the wrong place. `client.verify()` does
 * validate against the same schema, so a malformed claim was caught by the
 * relying party — after the token had been signed, written into the refresh
 * payload, and handed to anything else holding it. Validating here turns a
 * late failure in another service into an immediate local one.
 *
 * Second, the types were unsound. `SubjectPayload` declares
 * `properties: v1.InferOutput<T[type]>` — the schema's *parsed output* —
 * but with no parse anywhere the runtime value was the raw input. Any
 * schema carrying a transform or a default had a declared type that lied.
 * Returning the validated value is what makes that declaration true, and
 * it makes the issued token agree with what `client.verify()` will hand
 * back to the RP.
 *
 * Standard Schema keeps this validator spec-neutral (zod, valibot,
 * arktype) and adds no dependency the public surface didn't already have.
 */
import type { AuthError } from "../types/error"
import { authError } from "../types/error"
import type { Result } from "../types/result"
import { err, ok } from "../types/result"
import type { SubjectClaim, SubjectSchema } from "../types/subject"

/** Why a claim was rejected — enough for an operator, never the values. */
export type SubjectClaimRejection = {
  reason: "unknown-type" | "invalid-properties"
  /** The offending `claim.type`. Host-declared, safe to log. */
  subjectType: string
  /** Standard Schema issue path, or the list of declared types. */
  detail: string
}

/**
 * Validate the host's `SubjectClaim` against its own declared schema.
 *
 * On success the returned claim carries the **parsed** properties, which
 * is what gets signed and persisted. On failure the caller emits an
 * `invalid_subject_claim` audit event and returns a server error: the
 * host's callback broke its own contract, which is a deployment fault,
 * not something the relying party did wrong.
 */
export async function validateSubjectClaim(
  subjects: SubjectSchema,
  claim: SubjectClaim,
): Promise<
  Result<SubjectClaim, AuthError & { rejection: SubjectClaimRejection }>
> {
  const declared = Object.keys(subjects)
  const subjectType = typeof claim?.type === "string" ? claim.type : ""

  const schema = subjectType ? subjects[subjectType] : undefined
  if (!schema) {
    return err(
      Object.assign(
        authError.serverError(
          `success() returned subject type "${subjectType}", which is not declared in \`subjects\``,
        ),
        {
          rejection: {
            reason: "unknown-type" as const,
            subjectType,
            detail: `declared: ${declared.join(", ") || "(none)"}`,
          },
        },
      ),
    )
  }

  const validated = await schema["~standard"].validate(claim.properties)
  if (validated.issues) {
    // Paths only — the values themselves may be personal data.
    const detail =
      validated.issues
        .map((i) => (i.path ?? []).map(String).join(".") || "(root)")
        .join(", ") || "(root)"
    return err(
      Object.assign(
        authError.serverError(
          `success() returned properties that violate the "${subjectType}" schema`,
        ),
        {
          rejection: {
            reason: "invalid-properties" as const,
            subjectType,
            detail,
          },
        },
      ),
    )
  }

  return ok({
    type: subjectType,
    properties: validated.value,
  } as SubjectClaim)
}
