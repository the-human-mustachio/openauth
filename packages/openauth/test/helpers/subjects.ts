/**
 * Permissive `SubjectSchema` for tests that aren't themselves about
 * subject validation.
 *
 * Since 0.14.0 the server validates the claim `success()` returns against
 * the host's declared `subjects` before signing anything, so every test
 * that drives issuance needs a schema covering the types it emits. Tests
 * exercising the validation itself declare their own strict schemas —
 * see `test/domain/subject-validation.test.ts`.
 *
 * A passthrough object accepts any properties: these tests assert on token
 * plumbing, not on claim shape, and a strict schema here would couple
 * unrelated tests to whatever fixture properties they happen to pass.
 */
import { z } from "zod"

import type { SubjectSchema } from "../../src/types/subject"

const any = z.object({}).passthrough()

/** Covers the subject types used across the suite's fixtures. */
export const testSubjects: SubjectSchema = {
  user: any,
  service: any,
  orgMember: any,
  custom: any,
  admin: any,
}
