/**
 * Postgres `TokenStore`.
 *
 * - `consumeCode` is an atomic `DELETE … RETURNING` so concurrent
 *   presentations of the same code resolve to exactly one winner. The
 *   ciphertext blob is stored verbatim — `domain/authorize.ts` encrypts
 *   payloads before they reach the adapter (M1), and `domain/token.ts`
 *   decrypts after consume. The DB never sees plaintext.
 * - `consumeRefresh` does an atomic `UPDATE … WHERE consumed_at IS NULL
 *   RETURNING payload` so a refresh chain has a single live winner per
 *   generation. Reuse-detection within the configurable window auto-revokes
 *   the family.
 *
 * On reuse-detection the adapter returns `invalid_grant` and populates
 * the structured `reuseSignal` carrier on the error (family / tenantId /
 * subjectId), per the `TokenStore` port contract. The domain's audit
 * emission consumes the typed signal directly — no string parsing.
 */
import type { KeyStore } from "../../ports/key-store"
import type { TokenStore } from "../../ports/token-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantId } from "../../types/tenant"
import type { RefreshTokenPayload } from "../../types/token"

import type { PostgresExecutor } from "./executor"

const AUTH_CODE_MAX_TTL_MS = 60_000

export type PostgresTokenStoreOptions = {
  exec: PostgresExecutor
  /**
   * Optional — retained for API stability after M1 moved code-payload
   * encryption to the domain layer. The adapter no longer touches it.
   */
  keyStore?: KeyStore
  /** Injectable clock — defaults to `Date.now`. Tests advance it. */
  clock?: () => number
}

export class PostgresTokenStore implements TokenStore {
  #exec: PostgresExecutor
  #clock: () => number

  constructor(opts: PostgresTokenStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async saveCode(
    code: string,
    ciphertext: string,
    ttl: number,
  ): Promise<Result<void>> {
    if (ttl <= 0 || ttl > AUTH_CODE_MAX_TTL_MS) {
      return err(
        authError.internalError(
          `saveCode: ttl ${ttl} outside (0, ${AUTH_CODE_MAX_TTL_MS}] (auth-code TTL is fixed at 60s by OAuth 2.1 BCP)`,
        ),
      )
    }
    const expiresAt = this.#clock() + ttl
    try {
      await this.#exec.query(
        `INSERT INTO openauth_codes (code, ciphertext, expires_at) VALUES ($1, $2, $3)`,
        [code, ciphertext, expiresAt],
      )
    } catch (e) {
      return err(authError.internalError("saveCode: insert failed", e))
    }
    return ok(undefined)
  }

  async consumeCode(code: string): Promise<Result<string>> {
    let row: { ciphertext: string; expires_at: string | number } | undefined
    try {
      const result = await this.#exec.query<{
        ciphertext: string
        expires_at: string | number
      }>(
        `DELETE FROM openauth_codes WHERE code = $1 RETURNING ciphertext, expires_at`,
        [code],
      )
      row = result.rows[0]
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
    return ok(row.ciphertext)
  }

  async saveRefresh(
    refresh: string,
    payload: RefreshTokenPayload,
  ): Promise<Result<void>> {
    try {
      await this.#exec.query(
        `INSERT INTO openauth_refresh_tokens
           (token, tenant_id, client_id, subject_id, family, expires_at, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
        [
          refresh,
          payload.tenantId,
          payload.clientId,
          payload.subjectId,
          payload.family,
          payload.expiresAt,
          JSON.stringify(payload),
        ],
      )
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
    // First try to atomically claim the token — exactly one concurrent caller
    // gets a row back. The UPDATE bounds-checks expiry under the same row
    // lock so an expired token won't be marked consumed under us.
    let claimed: { payload: unknown } | undefined
    try {
      const result = await this.#exec.query<{ payload: unknown }>(
        `UPDATE openauth_refresh_tokens
           SET consumed_at = $1
         WHERE token = $2
           AND consumed_at IS NULL
           AND expires_at > $1
         RETURNING payload`,
        [now, refresh],
      )
      claimed = result.rows[0]
    } catch (e) {
      return err(authError.internalError("consumeRefresh: claim failed", e))
    }
    if (claimed) {
      return ok(parseRefreshPayload(claimed.payload))
    }
    // No row claimed. Find out why — unknown, expired, or already consumed.
    let existing:
      | { consumed_at: string | number | null; expires_at: string | number; payload: unknown }
      | undefined
    try {
      const result = await this.#exec.query<{
        consumed_at: string | number | null
        expires_at: string | number
        payload: unknown
      }>(
        `SELECT consumed_at, expires_at, payload
           FROM openauth_refresh_tokens
          WHERE token = $1`,
        [refresh],
      )
      existing = result.rows[0]
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
        const payload = parseRefreshPayload(existing.payload)
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
    // Should be unreachable — the UPDATE matched neither, but the row is
    // unconsumed and unexpired. Surface as internal so we notice.
    return err(authError.internalError("consumeRefresh: unexplained miss"))
  }

  async peekRefresh(
    refresh: string,
  ): Promise<Result<RefreshTokenPayload>> {
    let row:
      | { expires_at: string | number; payload: unknown }
      | undefined
    try {
      const result = await this.#exec.query<{
        expires_at: string | number
        payload: unknown
      }>(
        `SELECT expires_at, payload
           FROM openauth_refresh_tokens
          WHERE token = $1`,
        [refresh],
      )
      row = result.rows[0]
    } catch (e) {
      return err(authError.internalError("peekRefresh: lookup failed", e))
    }
    if (!row) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (this.#clock() >= Number(row.expires_at)) {
      return err(authError.invalidGrant("refresh token expired"))
    }
    return ok(parseRefreshPayload(row.payload))
  }

  async revokeFamily(family: string): Promise<Result<void>> {
    try {
      await this.#exec.query(
        `DELETE FROM openauth_refresh_tokens WHERE family = $1`,
        [family],
      )
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
      await this.#exec.query(
        `DELETE FROM openauth_refresh_tokens
          WHERE tenant_id = $1 AND subject_id = $2`,
        [tenantId, subjectId],
      )
    } catch (e) {
      return err(authError.internalError("revokeBySubject: delete failed", e))
    }
    return ok(undefined)
  }
}

function parseRefreshPayload(raw: unknown): RefreshTokenPayload {
  // PGlite returns parsed JSON; postgres-js may return a string depending on
  // pool config. Be tolerant of both.
  if (typeof raw === "string") return JSON.parse(raw) as RefreshTokenPayload
  return raw as RefreshTokenPayload
}
