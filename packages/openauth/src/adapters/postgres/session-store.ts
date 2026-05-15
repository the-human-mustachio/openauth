/**
 * Postgres `SessionStore` — flow records + optional long-lived sessions.
 *
 * `consumeFlow` is `DELETE … RETURNING payload, expires_at` — atomic
 * single-winner, returns the full record so the framework can snapshot
 * fields into the auth-code payload before disposal.
 *
 * `updateFlowMethodState` merges new state into the existing JSONB blob via
 * a single UPDATE (no read-modify-write race).
 */
import { authError } from "../../types/error"
import type { FlowRecord } from "../../types/flow"
import type { SessionRecord, SessionStore } from "../../ports/session-store"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type { PostgresExecutor } from "./executor"

export type PostgresSessionStoreOptions = {
  exec: PostgresExecutor
  clock?: () => number
}

export class PostgresSessionStore implements SessionStore {
  #exec: PostgresExecutor
  #clock: () => number

  constructor(opts: PostgresSessionStoreOptions) {
    this.#exec = opts.exec
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
      await this.#exec.query(
        `INSERT INTO openauth_flows (flow_id, payload, expires_at)
         VALUES ($1, $2::jsonb, $3)`,
        [flowId, JSON.stringify(payload), expiresAt],
      )
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
    let row: { exists: boolean } | undefined
    try {
      // jsonb_set patches the nested key without a read-modify-write race.
      const result = await this.#exec.query<{ exists: boolean }>(
        `UPDATE openauth_flows
            SET payload = jsonb_set(payload, '{methodState}', $1::jsonb, true)
          WHERE flow_id = $2 AND expires_at > $3
          RETURNING true AS exists`,
        [JSON.stringify(methodState), flowId, now],
      )
      row = result.rows[0]
    } catch (e) {
      return err(
        authError.internalError("updateFlowMethodState: update failed", e),
      )
    }
    if (!row) {
      return err(authError.unknownState(`flow "${flowId}" unknown or expired`))
    }
    return ok(undefined)
  }

  async readFlow(flowId: string): Promise<Result<FlowRecord>> {
    let row: { payload: unknown; expires_at: string | number } | undefined
    try {
      const result = await this.#exec.query<{
        payload: unknown
        expires_at: string | number
      }>(`SELECT payload, expires_at FROM openauth_flows WHERE flow_id = $1`, [
        flowId,
      ])
      row = result.rows[0]
    } catch (e) {
      return err(authError.internalError("readFlow: query failed", e))
    }
    if (!row) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      // Lazy GC — best-effort delete, don't fail the read if the delete races.
      try {
        await this.#exec.query(
          `DELETE FROM openauth_flows WHERE flow_id = $1`,
          [flowId],
        )
      } catch {}
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(parseFlowRecord(row.payload))
  }

  async consumeFlow(flowId: string): Promise<Result<FlowRecord>> {
    let row: { payload: unknown; expires_at: string | number } | undefined
    try {
      // Atomic delete-on-read — single-winner under concurrent presentations.
      const result = await this.#exec.query<{
        payload: unknown
        expires_at: string | number
      }>(
        `DELETE FROM openauth_flows
          WHERE flow_id = $1
          RETURNING payload, expires_at`,
        [flowId],
      )
      row = result.rows[0]
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
    return ok(parseFlowRecord(row.payload))
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
      await this.#exec.query(
        `INSERT INTO openauth_sessions (session_id, payload, expires_at)
         VALUES ($1, $2::jsonb, $3)
         ON CONFLICT (session_id) DO UPDATE SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at`,
        [sessionId, JSON.stringify(payload), expiresAt],
      )
    } catch (e) {
      return err(authError.internalError("createSession: insert failed", e))
    }
    return ok(undefined)
  }

  async readSession(sessionId: string): Promise<Result<SessionRecord>> {
    let row: { payload: unknown; expires_at: string | number } | undefined
    try {
      const result = await this.#exec.query<{
        payload: unknown
        expires_at: string | number
      }>(
        `SELECT payload, expires_at FROM openauth_sessions WHERE session_id = $1`,
        [sessionId],
      )
      row = result.rows[0]
    } catch (e) {
      return err(authError.internalError("readSession: query failed", e))
    }
    if (!row) {
      return err(authError.invalidRequest(`session "${sessionId}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      try {
        await this.#exec.query(
          `DELETE FROM openauth_sessions WHERE session_id = $1`,
          [sessionId],
        )
      } catch {}
      return err(authError.invalidRequest(`session "${sessionId}" expired`))
    }
    return ok(parseSession(row.payload))
  }

  async revokeSession(sessionId: string): Promise<Result<void>> {
    try {
      await this.#exec.query(
        `DELETE FROM openauth_sessions WHERE session_id = $1`,
        [sessionId],
      )
    } catch (e) {
      return err(authError.internalError("revokeSession: delete failed", e))
    }
    return ok(undefined)
  }

  async saveScratch(
    key: string,
    value: string,
    ttlMs: number,
  ): Promise<Result<void>> {
    if (ttlMs <= 0) {
      return err(
        authError.internalError(
          `saveScratch: ttlMs must be positive, got ${ttlMs}`,
        ),
      )
    }
    const expiresAt = this.#clock() + ttlMs
    try {
      await this.#exec.query(
        `INSERT INTO openauth_scratch (scratch_key, value, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (scratch_key)
         DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
        [key, value, expiresAt],
      )
    } catch (e) {
      return err(authError.internalError("saveScratch: upsert failed", e))
    }
    return ok(undefined)
  }

  async readScratch(key: string): Promise<Result<string>> {
    let row: { value: string; expires_at: string | number } | undefined
    try {
      const result = await this.#exec.query<{
        value: string
        expires_at: string | number
      }>(
        `SELECT value, expires_at FROM openauth_scratch WHERE scratch_key = $1`,
        [key],
      )
      row = result.rows[0]
    } catch (e) {
      return err(authError.internalError("readScratch: query failed", e))
    }
    if (!row) {
      return err(authError.unknownState(`scratch "${key}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      // Lazy GC — best-effort, don't fail the read if the delete races.
      try {
        await this.#exec.query(
          `DELETE FROM openauth_scratch WHERE scratch_key = $1`,
          [key],
        )
      } catch {}
      return err(authError.unknownState(`scratch "${key}" expired`))
    }
    return ok(row.value)
  }

  async deleteScratch(key: string): Promise<Result<void>> {
    try {
      await this.#exec.query(
        `DELETE FROM openauth_scratch WHERE scratch_key = $1`,
        [key],
      )
    } catch (e) {
      return err(authError.internalError("deleteScratch: delete failed", e))
    }
    return ok(undefined)
  }
}

function parseFlowRecord(raw: unknown): FlowRecord {
  if (typeof raw === "string") return JSON.parse(raw) as FlowRecord
  return raw as FlowRecord
}

function parseSession(raw: unknown): SessionRecord {
  if (typeof raw === "string") return JSON.parse(raw) as SessionRecord
  return raw as SessionRecord
}
