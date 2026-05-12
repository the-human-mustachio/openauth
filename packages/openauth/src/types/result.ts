/**
 * Result<T, E> — explicit success / failure encoding used throughout the domain.
 *
 * Domain functions return `Result` instead of throwing. The HTTP layer is the
 * one place that converts `AuthError` into an HTTP response. Keeping the domain
 * throw-free makes composition (chaining validators, branching on error code)
 * straightforward and avoids hidden control flow.
 *
 * AD5 in `docs/plans/claude/idp-rebuild-plan.md`.
 */
import type { AuthError } from "./error"

export type Result<T, E = AuthError> =
  | { ok: true; value: T }
  | { ok: false; error: E }

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value })
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error })

export const isOk = <T, E>(r: Result<T, E>): r is { ok: true; value: T } =>
  r.ok === true
export const isErr = <T, E>(r: Result<T, E>): r is { ok: false; error: E } =>
  r.ok === false
