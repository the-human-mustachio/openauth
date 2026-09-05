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
import type { FlowRecord } from "../types/flow"
import type { Result } from "../types/result"

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
   * **Peek** at a flow record without consuming it. Used by the method-route
   * mount (Phase 4) where credential POSTs may need to dispatch the
   * method multiple times before the flow is consumed on `success`.
   *
   * Consistency: strong (the record must be visible to a `consumeFlow`
   * called immediately after). Returns `unknown_state` if missing /
   * expired.
   *
   * The framework is the only legitimate caller; methods should never read
   * the flow directly — they observe via `MethodContext.flow`.
   */
  readFlow(flowId: string): Promise<Result<FlowRecord>>

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

  /**
   * Optional: Pushed Authorization Request (RFC 9126) storage. Persists the
   * pre-parsed `/authorize` parameters under an opaque `request_uri` for
   * one-shot retrieval at `/authorize` time. Strong consistency + atomic
   * delete-on-read — same semantics as `saveFlow` / `consumeFlow`.
   *
   * Adapters without these methods cannot satisfy `/par`; the framework's
   * `/par` handler returns `invalid_request` when called against such a
   * store. Implement both methods together (the framework only exposes
   * the endpoint when both are present).
   */
  savePar?(
    requestUri: string,
    payload: ParRecord,
    ttl: number,
  ): Promise<Result<void>>
  consumePar?(requestUri: string): Promise<Result<ParRecord>>

  /**
   * Optional: per-method-instance scratch storage. Survives across flows
   * (unlike `methodState`, which is per-flow). Use cases include cross-flow
   * deduplication state — e.g., a SAML SP method remembering recently-seen
   * assertion IDs for replay protection.
   *
   * The framework scopes keys per `(tenantId, methodId)` before calling
   * these — adapters see opaque, already-namespaced keys and store the
   * UTF-8 string value verbatim. Methods JSON-encode if they want object
   * state.
   *
   * Strong consistency + TTL respect (same semantics as flow records).
   * `readScratch` returns `unknown_state` if the key is missing or
   * expired. `deleteScratch` is idempotent.
   *
   * Adapters without these methods cannot host methods that depend on
   * scratch; the framework surfaces a clear `unsupported` error through
   * `MethodContext.methodScratch` at call time. Implement all three
   * methods together — partial implementations are not supported.
   */
  saveScratch?(key: string, value: string, ttlMs: number): Promise<Result<void>>
  readScratch?(key: string): Promise<Result<string>>
  deleteScratch?(key: string): Promise<Result<void>>
}

/**
 * Stored PAR payload. The `params` blob is the raw form/query record from
 * `POST /par`, kept verbatim so the `/authorize` rehydrate path can feed
 * it through the same Zod parser the direct path uses.
 */
export type ParRecord = {
  requestUri: string
  /** Raw key/value record as posted to `/par` (excluding auth fields). */
  params: Record<string, string>
  clientId: string
  /** Wall-clock issuance + absolute expiry (ms). */
  issuedAt: number
  expiresAt: number
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
