/**
 * DynamoDB `SessionStore`. Single-table — flows under `pk="flow"`, sessions
 * under `pk="session"`. `consumeFlow` is `DeleteItem` with `ReturnValues=ALL_OLD`
 * (atomic delete-on-read, single-winner under concurrent presentations).
 *
 * `updateFlowMethodState` reads then conditionally writes the merged payload
 * with `attribute_exists(pk) AND expires_at > :now`. If a concurrent
 * `consumeFlow` snuck in, the condition fails and we surface
 * `unknown_state`.
 */
import { authError } from "../../types/error"
import type { FlowRecord } from "../../types/flow"
import type { SessionRecord, SessionStore } from "../../ports/session-store"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type { DynamoExecutor } from "./client"

export type DynamoSessionStoreOptions = {
  exec: DynamoExecutor
  clock?: () => number
}

export class DynamoSessionStore implements SessionStore {
  #exec: DynamoExecutor
  #clock: () => number

  constructor(opts: DynamoSessionStoreOptions) {
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
    const expiresAtMs = this.#clock() + ttl
    try {
      await this.#exec.put({
        item: {
          pk: "flow",
          sk: flowId,
          payload: JSON.stringify(payload),
          expires_at: expiresAtMs,
          ttl: Math.floor(expiresAtMs / 1000),
        },
      })
    } catch (e) {
      return err(authError.internalError("saveFlow: put failed", e))
    }
    return ok(undefined)
  }

  async updateFlowMethodState(
    flowId: string,
    methodState: unknown,
  ): Promise<Result<void>> {
    const now = this.#clock()
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.get({
        key: { pk: "flow", sk: flowId },
        consistentRead: true,
      })
    } catch (e) {
      return err(authError.internalError("updateFlowMethodState: get failed", e))
    }
    if (!row) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (now >= Number(row.expires_at)) {
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    const parsed = parseFlowPayload(row.payload)
    const next = { ...parsed, methodState }
    try {
      // `condition: "exists"` translates to `attribute_exists(pk) AND
      // attribute_exists(sk)`. If a concurrent `consumeFlow` deleted the row
      // between our `get` and this `put`, the put fails instead of
      // resurrecting the deleted row — which would otherwise let the original
      // caller re-consume and bypass flow-reuse detection.
      await this.#exec.put({
        item: {
          pk: "flow",
          sk: flowId,
          payload: JSON.stringify(next),
          expires_at: row.expires_at,
          ttl: row.ttl,
        },
        condition: "exists",
      })
    } catch (e) {
      if (isConditionalCheckFailed(e)) {
        return err(
          authError.unknownState(
            `flow "${flowId}" was consumed between read and update`,
          ),
        )
      }
      return err(authError.internalError("updateFlowMethodState: put failed", e))
    }
    return ok(undefined)
  }

  async readFlow(flowId: string): Promise<Result<FlowRecord>> {
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.get({
        key: { pk: "flow", sk: flowId },
        consistentRead: true,
      })
    } catch (e) {
      return err(authError.internalError("readFlow: get failed", e))
    }
    if (!row) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      try {
        await this.#exec.delete({ key: { pk: "flow", sk: flowId } })
      } catch {}
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(parseFlowPayload(row.payload))
  }

  async consumeFlow(flowId: string): Promise<Result<FlowRecord>> {
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.delete({ key: { pk: "flow", sk: flowId } })
    } catch (e) {
      return err(authError.internalError("consumeFlow: delete failed", e))
    }
    if (!row) {
      return err(
        authError.unknownState(`flow "${flowId}" unknown or already consumed`),
      )
    }
    if (this.#clock() >= Number(row.expires_at)) {
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(parseFlowPayload(row.payload))
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
    const expiresAtMs = this.#clock() + ttl
    try {
      await this.#exec.put({
        item: {
          pk: "session",
          sk: sessionId,
          payload: JSON.stringify(payload),
          expires_at: expiresAtMs,
          ttl: Math.floor(expiresAtMs / 1000),
        },
      })
    } catch (e) {
      return err(authError.internalError("createSession: put failed", e))
    }
    return ok(undefined)
  }

  async readSession(sessionId: string): Promise<Result<SessionRecord>> {
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.get({
        key: { pk: "session", sk: sessionId },
        consistentRead: true,
      })
    } catch (e) {
      return err(authError.internalError("readSession: get failed", e))
    }
    if (!row) {
      return err(authError.invalidRequest(`session "${sessionId}" unknown`))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      try {
        await this.#exec.delete({ key: { pk: "session", sk: sessionId } })
      } catch {}
      return err(authError.invalidRequest(`session "${sessionId}" expired`))
    }
    return ok(parseSessionPayload(row.payload))
  }

  async revokeSession(sessionId: string): Promise<Result<void>> {
    try {
      await this.#exec.delete({ key: { pk: "session", sk: sessionId } })
    } catch (e) {
      return err(authError.internalError("revokeSession: delete failed", e))
    }
    return ok(undefined)
  }
}

function parseFlowPayload(raw: unknown): FlowRecord {
  if (typeof raw === "string") return JSON.parse(raw) as FlowRecord
  return raw as FlowRecord
}

function isConditionalCheckFailed(e: unknown): boolean {
  if (typeof e !== "object" || e === null) return false
  return (e as { name?: string }).name === "ConditionalCheckFailedException"
}

function parseSessionPayload(raw: unknown): SessionRecord {
  if (typeof raw === "string") return JSON.parse(raw) as SessionRecord
  return raw as SessionRecord
}
