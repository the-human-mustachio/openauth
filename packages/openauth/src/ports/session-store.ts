/**
 * `SessionStore` — flow records (required) and optional long-lived sessions.
 *
 * Flow records are the single server-side source of truth for an in-flight
 * authorization. They are written at `/authorize`, updated when a method
 * returns a `challenge` with `saveMethodState`, and consumed exactly once
 * on the upstream callback.
 *
 * The framework owns flow-record I/O — methods only observe
 * (`MethodContext.flow`) and request updates via
 * `MethodResult.challenge.saveMethodState`. Methods MUST NOT call
 * `saveFlow` / `consumeFlow` directly.
 *
 * See `ports/CONSISTENCY.md`.
 */
import type { FlowRecord } from "../types/flow.js"
import type { Result } from "../types/result.js"

export type SessionStore = {
  /**
   * Persist a new flow record under `flowId`. Strong, atomic write — the
   * record must be visible to `consumeFlow` on any node by the time this
   * resolves. `ttl` is in milliseconds and must equal `expiresAt -
   * createdAt` on the supplied record (default 10 minutes).
   */
  saveFlow(
    flowId: string,
    payload: FlowRecord,
    ttl: number,
  ): Promise<Result<void>>

  /**
   * Merge `methodState` into an existing flow record. The framework calls
   * this when a method handler returns
   * `{ kind: "challenge", saveMethodState }`, **before** sending the
   * upstream redirect response — the user agent never sees the redirect
   * until `methodState` is durably saved.
   *
   * Returns `unknown_state` if `flowId` is missing or already consumed.
   */
  updateFlowMethodState(
    flowId: string,
    methodState: unknown,
  ): Promise<Result<void>>

  /**
   * Atomic delete-on-read. Returns the full `FlowRecord` on success — the
   * framework needs every field to snapshot into the auth-code payload
   * before the record is gone. Concurrent calls with the same `flowId`
   * resolve to exactly one winner; losers receive `unknown_state` which
   * the HTTP layer maps to `invalid_request` (audit
   * `flow_replay_attempt`).
   *
   * This is the **only** consume; the framework does not call it twice.
   * Methods receive the in-memory record via `MethodContext.flow` for the
   * rest of the callback request.
   */
  consumeFlow(flowId: string): Promise<Result<FlowRecord>>

  /**
   * Optional: long-lived session support (cross-request remember-me beyond
   * the OAuth flow). Adapters that don't implement this can omit it; the
   * framework only requires the flow-record methods above.
   */
  createSession?(
    sessionId: string,
    payload: SessionRecord,
    ttl: number,
  ): Promise<Result<void>>
  readSession?(sessionId: string): Promise<Result<SessionRecord>>
  revokeSession?(sessionId: string): Promise<Result<void>>
}

/** Optional long-lived session payload (used by `createSession` family). */
export type SessionRecord = {
  sessionId: string
  tenantId: string
  subjectId: string
  /** Wall-clock issued / expires timestamps (ms). */
  issuedAt: number
  expiresAt: number
  /** Free-form metadata adapters may use (device, user agent fingerprint, etc.). */
  metadata?: Record<string, unknown>
}
