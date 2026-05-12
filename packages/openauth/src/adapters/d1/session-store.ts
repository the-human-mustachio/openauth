/**
 * D1 `SessionStore`. Flow records + optional long-lived sessions.
 *
 * `consumeFlow` is `DELETE … RETURNING payload, expires_at` — atomic
 * single-winner. `updateFlowMethodState` re-serializes the entire payload
 * blob (SQLite has no `jsonb_set`); the read-then-write is wrapped inside
 * the same `primarySession` so the bookmark advances atomically.
 */
import { authError } from "../../types/error"
import type { FlowRecord } from "../../types/flow"
import type { SessionRecord, SessionStore } from "../../ports/session-store"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import { primarySession } from "./session"
import type { AnyD1Database } from "./types"

export type D1SessionStoreOptions = {
  db: AnyD1Database
  clock?: () => number
}

export class D1SessionStore implements SessionStore {
  #db: AnyD1Database
  #clock: () => number

  constructor(opts: D1SessionStoreOptions) {
    this.#db = opts.db
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async saveFlow(
    flowId: string,
    payload: FlowRecord,
    ttl: number,
  ): Promise<Result<void>> {
    if (ttl <= 0) {
      return err(
        authError.internalError(`saveFlow: ttl must be positive, got ${ttl}`),
      )
    }
    const expiresAt = this.#clock() + ttl
    try {
      await primarySession(this.#db)
        .prepare(
          `INSERT INTO openauth_flows (flow_id, payload, expires_at) VALUES (?1, ?2, ?3)`,
        )
        .bind(flowId, JSON.stringify(payload), expiresAt)
        .run()
    } catch (e) {
      return err(authError.internalError("saveFlow: insert failed", e))
    }
    return ok(undefined)
  }

  async updateFlowMethodState(
    flowId: string,
    methodState: unknown,
  ): Promise<Result<void>> {
    const now = this.#clock()
    const session = primarySession(this.#db)
    let row: { payload: string; expires_at: number } | null
    try {
      row = await session
        .prepare(
          `SELECT payload, expires_at FROM openauth_flows WHERE flow_id = ?1`,
        )
        .bind(flowId)
        .first<{ payload: string; expires_at: number }>()
    } catch (e) {
      return err(
        authError.internalError("updateFlowMethodState: read failed", e),
      )
    }
    if (!row) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (now >= Number(row.expires_at)) {
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    let parsed: FlowRecord
    try {
      parsed = JSON.parse(row.payload) as FlowRecord
    } catch (e) {
      return err(
        authError.internalError("updateFlowMethodState: parse failed", e),
      )
    }
    const next = { ...parsed, methodState }
    try {
      // Conditional write — only update if the row still exists AND has
      // matching expiry. If a concurrent consume snuck in, the WHERE clause
      // misses and we surface `unknown_state`.
      const result = await session
        .prepare(
          `UPDATE openauth_flows SET payload = ?1
            WHERE flow_id = ?2 AND expires_at > ?3
            RETURNING 1 AS hit`,
        )
        .bind(JSON.stringify(next), flowId, now)
        .first<{ hit: number }>()
      if (!result) {
        return err(
          authError.unknownState(`flow "${flowId}" unknown or expired`),
        )
      }
    } catch (e) {
      return err(
        authError.internalError("updateFlowMethodState: update failed", e),
      )
    }
    return ok(undefined)
  }

  async readFlow(flowId: string): Promise<Result<FlowRecord>> {
    let row: { payload: string; expires_at: number } | null
    try {
      row = await primarySession(this.#db)
        .prepare(
          `SELECT payload, expires_at FROM openauth_flows WHERE flow_id = ?1`,
        )
        .bind(flowId)
        .first<{ payload: string; expires_at: number }>()
    } catch (e) {
      return err(authError.internalError("readFlow: query failed", e))
    }
    if (!row) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      try {
        await primarySession(this.#db)
          .prepare(`DELETE FROM openauth_flows WHERE flow_id = ?1`)
          .bind(flowId)
          .run()
      } catch {}
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(JSON.parse(row.payload) as FlowRecord)
  }

  async consumeFlow(flowId: string): Promise<Result<FlowRecord>> {
    let row: { payload: string; expires_at: number } | null
    try {
      row = await primarySession(this.#db)
        .prepare(
          `DELETE FROM openauth_flows WHERE flow_id = ?1 RETURNING payload, expires_at`,
        )
        .bind(flowId)
        .first<{ payload: string; expires_at: number }>()
    } catch (e) {
      return err(authError.internalError("consumeFlow: query failed", e))
    }
    if (!row) {
      return err(
        authError.unknownState(`flow "${flowId}" unknown or already consumed`),
      )
    }
    if (this.#clock() >= Number(row.expires_at)) {
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(JSON.parse(row.payload) as FlowRecord)
  }

  async createSession(
    sessionId: string,
    payload: SessionRecord,
    ttl: number,
  ): Promise<Result<void>> {
    if (ttl <= 0) {
      return err(
        authError.internalError(
          `createSession: ttl must be positive, got ${ttl}`,
        ),
      )
    }
    const expiresAt = this.#clock() + ttl
    try {
      await primarySession(this.#db)
        .prepare(
          `INSERT INTO openauth_sessions (session_id, payload, expires_at) VALUES (?1, ?2, ?3)
           ON CONFLICT(session_id) DO UPDATE SET payload = excluded.payload, expires_at = excluded.expires_at`,
        )
        .bind(sessionId, JSON.stringify(payload), expiresAt)
        .run()
    } catch (e) {
      return err(authError.internalError("createSession: insert failed", e))
    }
    return ok(undefined)
  }

  async readSession(sessionId: string): Promise<Result<SessionRecord>> {
    let row: { payload: string; expires_at: number } | null
    try {
      row = await primarySession(this.#db)
        .prepare(
          `SELECT payload, expires_at FROM openauth_sessions WHERE session_id = ?1`,
        )
        .bind(sessionId)
        .first<{ payload: string; expires_at: number }>()
    } catch (e) {
      return err(authError.internalError("readSession: query failed", e))
    }
    if (!row) {
      return err(authError.invalidRequest(`session "${sessionId}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      try {
        await primarySession(this.#db)
          .prepare(`DELETE FROM openauth_sessions WHERE session_id = ?1`)
          .bind(sessionId)
          .run()
      } catch {}
      return err(authError.invalidRequest(`session "${sessionId}" expired`))
    }
    return ok(JSON.parse(row.payload) as SessionRecord)
  }

  async revokeSession(sessionId: string): Promise<Result<void>> {
    try {
      await primarySession(this.#db)
        .prepare(`DELETE FROM openauth_sessions WHERE session_id = ?1`)
        .bind(sessionId)
        .run()
    } catch (e) {
      return err(authError.internalError("revokeSession: delete failed", e))
    }
    return ok(undefined)
  }
}
