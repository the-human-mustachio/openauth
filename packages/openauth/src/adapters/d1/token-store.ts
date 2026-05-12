/**
 * D1 `TokenStore`. SQL-identical to the Postgres adapter except for SQLite
 * dialect (`?N` binds, JSON-as-TEXT, BLOB) and the Sessions-API wrapping
 * for read-after-write consistency.
 *
 * Every operation here is on the security-critical path and uses
 * `primarySession(db)` so reads always see the latest write — per AD8 + the
 * D1 read-replication caveat in `ports/CONSISTENCY.md`.
 */
import { decryptPayload, encryptPayload } from "../../domain/crypto"
import type { KeyStore } from "../../ports/key-store"
import type { TokenStore } from "../../ports/token-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, isErr, ok } from "../../types/result"
import type { TenantId } from "../../types/tenant"
import type { CodePayload, RefreshTokenPayload } from "../../types/token"

import { primarySession } from "./session"
import type { AnyD1Database } from "./types"

const AUTH_CODE_MAX_TTL_MS = 60_000

export type D1TokenStoreOptions = {
  db: AnyD1Database
  keyStore: KeyStore
  clock?: () => number
}

export class D1TokenStore implements TokenStore {
  #db: AnyD1Database
  #keyStore: KeyStore
  #clock: () => number

  constructor(opts: D1TokenStoreOptions) {
    this.#db = opts.db
    this.#keyStore = opts.keyStore
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async saveCode(
    code: string,
    payload: CodePayload,
    ttl: number,
  ): Promise<Result<void>> {
    if (ttl <= 0 || ttl > AUTH_CODE_MAX_TTL_MS) {
      return err(
        authError.internalError(
          `saveCode: ttl ${ttl} outside (0, ${AUTH_CODE_MAX_TTL_MS}] (auth-code TTL is fixed at 60s by OAuth 2.1 BCP)`,
        ),
      )
    }
    const keyResult = await this.#keyStore.currentEncryptionKey()
    if (isErr(keyResult)) return keyResult
    let jwe: string
    try {
      jwe = await encryptPayload(
        payload,
        keyResult.value.kid,
        keyResult.value.keyRef as Uint8Array,
      )
    } catch (e) {
      return err(authError.internalError("saveCode: encrypt failed", e))
    }
    const expiresAt = this.#clock() + ttl
    try {
      await primarySession(this.#db)
        .prepare(
          `INSERT INTO openauth_codes (code, ciphertext, expires_at) VALUES (?1, ?2, ?3)`,
        )
        .bind(code, jwe, expiresAt)
        .run()
    } catch (e) {
      return err(authError.internalError("saveCode: insert failed", e))
    }
    return ok(undefined)
  }

  async consumeCode(code: string): Promise<Result<CodePayload>> {
    let row: { ciphertext: string; expires_at: number } | null
    try {
      row = await primarySession(this.#db)
        .prepare(
          `DELETE FROM openauth_codes WHERE code = ?1 RETURNING ciphertext, expires_at`,
        )
        .bind(code)
        .first<{ ciphertext: string; expires_at: number }>()
    } catch (e) {
      return err(authError.internalError("consumeCode: query failed", e))
    }
    if (!row) {
      return err(
        authError.invalidGrant("auth code unknown or already consumed"),
      )
    }
    if (this.#clock() >= Number(row.expires_at)) {
      return err(authError.invalidGrant("auth code expired"))
    }
    try {
      const payload = await decryptPayload<CodePayload>(
        row.ciphertext,
        async (kid) => {
          const keyResult = await this.#keyStore.getEncryptionKey(kid)
          if (isErr(keyResult)) throw new Error(`unknown encryption kid ${kid}`)
          return keyResult.value.keyRef as Uint8Array
        },
      )
      return ok(payload)
    } catch (e) {
      return err(authError.internalError("consumeCode: decrypt failed", e))
    }
  }

  async saveRefresh(
    refresh: string,
    payload: RefreshTokenPayload,
  ): Promise<Result<void>> {
    try {
      await primarySession(this.#db)
        .prepare(
          `INSERT INTO openauth_refresh_tokens
             (token, tenant_id, client_id, subject_id, family, expires_at, payload)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
        )
        .bind(
          refresh,
          payload.tenantId,
          payload.clientId,
          payload.subjectId,
          payload.family,
          payload.expiresAt,
          JSON.stringify(payload),
        )
        .run()
    } catch (e) {
      return err(authError.internalError("saveRefresh: insert failed", e))
    }
    return ok(undefined)
  }

  async consumeRefresh(
    refresh: string,
    options: { reuseWindowMs?: number } = {},
  ): Promise<Result<RefreshTokenPayload>> {
    const reuseWindow = options.reuseWindowMs ?? 60_000
    const now = this.#clock()
    const session = primarySession(this.#db)
    // Atomic claim — SQLite's UPDATE ... RETURNING is available from 3.35
    // (D1 ships much newer). One row out means we won the race.
    let claimed: { payload: string } | null
    try {
      claimed = await session
        .prepare(
          `UPDATE openauth_refresh_tokens
             SET consumed_at = ?1
           WHERE token = ?2
             AND consumed_at IS NULL
             AND expires_at > ?1
           RETURNING payload`,
        )
        .bind(now, refresh)
        .first<{ payload: string }>()
    } catch (e) {
      return err(authError.internalError("consumeRefresh: claim failed", e))
    }
    if (claimed) {
      return ok(parseRefresh(claimed.payload))
    }
    // No claim — figure out why.
    let existing: {
      consumed_at: number | null
      expires_at: number
      payload: string
    } | null
    try {
      existing = await session
        .prepare(
          `SELECT consumed_at, expires_at, payload
             FROM openauth_refresh_tokens
            WHERE token = ?1`,
        )
        .bind(refresh)
        .first<{ consumed_at: number | null; expires_at: number; payload: string }>()
    } catch (e) {
      return err(authError.internalError("consumeRefresh: lookup failed", e))
    }
    if (!existing) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (existing.consumed_at !== null && existing.consumed_at !== undefined) {
      const consumedAt = Number(existing.consumed_at)
      const withinWindow = now - consumedAt <= reuseWindow
      if (withinWindow) {
        const payload = parseRefresh(existing.payload)
        await this.revokeFamily(payload.family)
        return err(
          authError.invalidGrant(
            `refresh token reuse detected (family=${payload.family})`,
            {
              family: payload.family,
              tenantId: payload.tenantId,
              subjectId: payload.subjectId,
            },
          ),
        )
      }
      return err(authError.invalidGrant("refresh token already consumed"))
    }
    if (now >= Number(existing.expires_at)) {
      return err(authError.invalidGrant("refresh token expired"))
    }
    return err(authError.internalError("consumeRefresh: unexplained miss"))
  }

  async peekRefresh(
    refresh: string,
  ): Promise<Result<RefreshTokenPayload>> {
    let row: { expires_at: number; payload: string } | null
    try {
      row = await primarySession(this.#db)
        .prepare(
          `SELECT expires_at, payload
             FROM openauth_refresh_tokens
            WHERE token = ?1`,
        )
        .bind(refresh)
        .first<{ expires_at: number; payload: string }>()
    } catch (e) {
      return err(authError.internalError("peekRefresh: lookup failed", e))
    }
    if (!row) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      return err(authError.invalidGrant("refresh token expired"))
    }
    return ok(parseRefresh(row.payload))
  }

  async revokeFamily(family: string): Promise<Result<void>> {
    try {
      await primarySession(this.#db)
        .prepare(`DELETE FROM openauth_refresh_tokens WHERE family = ?1`)
        .bind(family)
        .run()
    } catch (e) {
      return err(authError.internalError("revokeFamily: delete failed", e))
    }
    return ok(undefined)
  }

  async revokeBySubject(
    tenantId: TenantId,
    subjectId: string,
  ): Promise<Result<void>> {
    try {
      await primarySession(this.#db)
        .prepare(
          `DELETE FROM openauth_refresh_tokens WHERE tenant_id = ?1 AND subject_id = ?2`,
        )
        .bind(tenantId, subjectId)
        .run()
    } catch (e) {
      return err(authError.internalError("revokeBySubject: delete failed", e))
    }
    return ok(undefined)
  }
}

function parseRefresh(raw: string | RefreshTokenPayload): RefreshTokenPayload {
  if (typeof raw === "string") return JSON.parse(raw) as RefreshTokenPayload
  return raw
}
