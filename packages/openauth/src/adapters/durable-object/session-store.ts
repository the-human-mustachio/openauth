/**
 * Durable Objects `SessionStore`. Per `ports/CONSISTENCY.md`, DOs are an
 * acceptable backing store for `SessionStore` (and optionally `TokenStore`)
 * because every operation on a single DO instance is serialized — atomic
 * delete-on-read comes for free with `storage.transaction`.
 *
 * Wiring pattern: the adapter accepts a `DurableObjectStorage` reference,
 * which the user supplies from inside their own DO class (`this.ctx.storage`).
 * The user is responsible for routing requests to the right DO instance —
 * typically one DO per flow-id (`namespace.idFromName(flowId)`), which keeps
 * the per-flow state co-located and serialized.
 *
 * @example
 *   // Worker module export
 *   export class IdpSessionDO {
 *     constructor(ctx) {
 *       this.store = new DurableObjectSessionStore({ storage: ctx.storage })
 *     }
 *     async fetch(req) {
 *       const { op, args } = await req.json()
 *       const result = await (this.store as any)[op](...args)
 *       return Response.json(result)
 *     }
 *   }
 *
 *   // Caller — round-trips through fetch
 *   const stub = env.IDP_SESSIONS.get(env.IDP_SESSIONS.idFromName(flowId))
 *   await stub.fetch("https://internal/", {
 *     method: "POST",
 *     body: JSON.stringify({ op: "consumeFlow", args: [flowId] }),
 *   })
 */
import { authError } from "../../types/error"
import type { FlowRecord } from "../../types/flow"
import type { SessionRecord, SessionStore } from "../../ports/session-store"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"

import type {
  DurableObjectStorageLike,
  DurableObjectTransactionLike,
} from "./types"

type StoredFlow = {
  record: FlowRecord
  expiresAt: number
}

type StoredSession = {
  record: SessionRecord
  expiresAt: number
}

type StoredScratch = {
  value: string
  expiresAt: number
}

export type DurableObjectSessionStoreOptions = {
  storage: DurableObjectStorageLike
  clock?: () => number
}

export class DurableObjectSessionStore implements SessionStore {
  #storage: DurableObjectStorageLike
  #clock: () => number

  constructor(opts: DurableObjectSessionStoreOptions) {
    this.#storage = opts.storage
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
    const stored: StoredFlow = {
      record: payload,
      expiresAt: this.#clock() + ttl,
    }
    try {
      await this.#storage.put(flowKey(flowId), stored)
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
    try {
      // Transaction so the read-then-write is atomic against concurrent
      // consumers on the same DO.
      const outcome = await this.#storage.transaction(async (txn) => {
        const existing = await txn.get<StoredFlow>(flowKey(flowId))
        if (!existing) return "unknown" as const
        if (now >= existing.expiresAt) return "expired" as const
        await txn.put(flowKey(flowId), {
          record: { ...existing.record, methodState },
          expiresAt: existing.expiresAt,
        })
        return "ok" as const
      })
      if (outcome === "unknown")
        return err(authError.unknownState(`flow "${flowId}" unknown`))
      if (outcome === "expired")
        return err(authError.unknownState(`flow "${flowId}" expired`))
    } catch (e) {
      return err(
        authError.internalError("updateFlowMethodState: transaction failed", e),
      )
    }
    return ok(undefined)
  }

  async readFlow(flowId: string): Promise<Result<FlowRecord>> {
    let stored: StoredFlow | undefined
    try {
      stored = await this.#storage.get<StoredFlow>(flowKey(flowId))
    } catch (e) {
      return err(authError.internalError("readFlow: get failed", e))
    }
    if (!stored) {
      return err(authError.unknownState(`flow "${flowId}" unknown`))
    }
    if (this.#clock() >= stored.expiresAt) {
      try {
        await this.#storage.delete(flowKey(flowId))
      } catch {}
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(stored.record)
  }

  async consumeFlow(flowId: string): Promise<Result<FlowRecord>> {
    let result:
      | { kind: "miss" }
      | { kind: "expired" }
      | { kind: "hit"; record: FlowRecord }
    try {
      result = await this.#storage.transaction(async (txn) => {
        const stored = await txn.get<StoredFlow>(flowKey(flowId))
        if (!stored) return { kind: "miss" as const }
        // Delete first to enforce single-winner semantics — any other caller
        // racing on the same flowId will see the key gone on its read.
        await txn.delete(flowKey(flowId))
        if (this.#clock() >= stored.expiresAt) {
          return { kind: "expired" as const }
        }
        return { kind: "hit" as const, record: stored.record }
      })
    } catch (e) {
      return err(authError.internalError("consumeFlow: transaction failed", e))
    }
    if (result.kind === "miss") {
      return err(
        authError.unknownState(`flow "${flowId}" unknown or already consumed`),
      )
    }
    if (result.kind === "expired") {
      return err(authError.unknownState(`flow "${flowId}" expired`))
    }
    return ok(result.record)
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
    const stored: StoredSession = {
      record: payload,
      expiresAt: this.#clock() + ttl,
    }
    try {
      await this.#storage.put(sessionKey(sessionId), stored)
    } catch (e) {
      return err(authError.internalError("createSession: put failed", e))
    }
    return ok(undefined)
  }

  async readSession(sessionId: string): Promise<Result<SessionRecord>> {
    let stored: StoredSession | undefined
    try {
      stored = await this.#storage.get<StoredSession>(sessionKey(sessionId))
    } catch (e) {
      return err(authError.internalError("readSession: get failed", e))
    }
    if (!stored) {
      return err(authError.invalidRequest(`session "${sessionId}" unknown`))
    }
    if (this.#clock() >= stored.expiresAt) {
      try {
        await this.#storage.delete(sessionKey(sessionId))
      } catch {}
      return err(authError.invalidRequest(`session "${sessionId}" expired`))
    }
    return ok(stored.record)
  }

  async revokeSession(sessionId: string): Promise<Result<void>> {
    try {
      await this.#storage.delete(sessionKey(sessionId))
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
    const stored: StoredScratch = {
      value,
      expiresAt: this.#clock() + ttlMs,
    }
    try {
      // Plain put — scratch overwrites any prior value for the key. No
      // transaction needed: it is a single write, and the DO serializes
      // all operations on this instance.
      await this.#storage.put(scratchKey(key), stored)
    } catch (e) {
      return err(authError.internalError("saveScratch: put failed", e))
    }
    return ok(undefined)
  }

  async readScratch(key: string): Promise<Result<string>> {
    let stored: StoredScratch | undefined
    try {
      stored = await this.#storage.get<StoredScratch>(scratchKey(key))
    } catch (e) {
      return err(authError.internalError("readScratch: get failed", e))
    }
    if (!stored) {
      return err(authError.unknownState(`scratch "${key}" unknown`))
    }
    if (this.#clock() >= stored.expiresAt) {
      try {
        await this.#storage.delete(scratchKey(key))
      } catch {}
      return err(authError.unknownState(`scratch "${key}" expired`))
    }
    return ok(stored.value)
  }

  async deleteScratch(key: string): Promise<Result<void>> {
    try {
      await this.#storage.delete(scratchKey(key))
    } catch (e) {
      return err(authError.internalError("deleteScratch: delete failed", e))
    }
    return ok(undefined)
  }
}

const flowKey = (flowId: string) => `flow:${flowId}`
const sessionKey = (sessionId: string) => `session:${sessionId}`
const scratchKey = (key: string) => `scratch:${key}`

// Re-exported for adapter users wiring `storage.transaction` callbacks.
export type { DurableObjectStorageLike, DurableObjectTransactionLike }
