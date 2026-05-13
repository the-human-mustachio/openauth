/**
 * In-memory `SessionStore` — flow records (required) + optional long-lived
 * sessions. Map-backed; atomic w.r.t. the JS event loop.
 *
 * `consumeFlow` is a strict atomic delete-on-read that returns the full
 * `FlowRecord` — the framework needs every field to snapshot into the
 * auth-code payload before the record is gone.
 */
import { authError } from "../../types/error"
import type { FlowRecord } from "../../types/flow"
import type {
  ParRecord,
  SessionRecord,
  SessionStore,
} from "../../ports/session-store"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { Clock } from "./clock"
import { realClock } from "./clock"

type StoredFlow = {
  record: FlowRecord
  expiresAt: number
}

type StoredPar = {
  record: ParRecord
  expiresAt: number
}

export type MemorySessionStoreOptions = {
  clock?: Clock
}

export class MemorySessionStore implements SessionStore {
  #clock: Clock
  #flows = new Map<string, StoredFlow>()
  #sessions = new Map<string, SessionRecord>()
  #par = new Map<string, StoredPar>()

  constructor(opts: MemorySessionStoreOptions = {}) {
    this.#clock = opts.clock ?? realClock
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
    this.#flows.set(flowId, {
      record: payload,
      expiresAt: this.#clock() + ttl,
    })
    return ok(undefined)
  }

  async updateFlowMethodState(
    flowId: string,
    methodState: unknown,
  ): Promise<Result<void>> {
    const stored = this.#flows.get(flowId)
    if (!stored) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (this.#clock() >= stored.expiresAt) {
      this.#flows.delete(flowId)
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    stored.record = { ...stored.record, methodState }
    return ok(undefined)
  }

  async readFlow(flowId: string): Promise<Result<FlowRecord>> {
    const stored = this.#flows.get(flowId)
    if (!stored) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (this.#clock() >= stored.expiresAt) {
      this.#flows.delete(flowId)
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(stored.record)
  }

  async consumeFlow(flowId: string): Promise<Result<FlowRecord>> {
    const stored = this.#flows.get(flowId)
    if (!stored) {
      return err(
        authError.unknownState(`flow "${flowId}" unknown or already consumed`),
      )
    }
    // Atomic delete-on-read — remove before observable side effects so a
    // concurrent caller can't see the same record.
    this.#flows.delete(flowId)
    if (this.#clock() >= stored.expiresAt) {
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(stored.record)
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
    this.#sessions.set(sessionId, payload)
    return ok(undefined)
  }

  async readSession(sessionId: string): Promise<Result<SessionRecord>> {
    const s = this.#sessions.get(sessionId)
    if (!s) {
      return err(authError.invalidRequest(`session "${sessionId}" unknown`))
    }
    if (this.#clock() >= s.expiresAt) {
      this.#sessions.delete(sessionId)
      return err(authError.invalidRequest(`session "${sessionId}" expired`))
    }
    return ok(s)
  }

  async revokeSession(sessionId: string): Promise<Result<void>> {
    this.#sessions.delete(sessionId)
    return ok(undefined)
  }

  async savePar(
    requestUri: string,
    payload: ParRecord,
    ttl: number,
  ): Promise<Result<void>> {
    if (ttl <= 0) {
      return err(
        authError.internalError(`savePar: ttl must be positive, got ${ttl}`),
      )
    }
    this.#par.set(requestUri, {
      record: payload,
      expiresAt: this.#clock() + ttl,
    })
    return ok(undefined)
  }

  async consumePar(requestUri: string): Promise<Result<ParRecord>> {
    const stored = this.#par.get(requestUri)
    if (!stored) {
      return err(
        authError.unknownState(
          `par "${requestUri}" unknown or already consumed`,
        ),
      )
    }
    this.#par.delete(requestUri)
    if (this.#clock() >= stored.expiresAt) {
      return err(authError.unknownState(`par "${requestUri}" expired`))
    }
    return ok(stored.record)
  }
}
