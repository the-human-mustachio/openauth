/**
 * In-memory `TokenStore`. Single-process; the `Map` operations are
 * atomic with respect to JS event-loop turns, which is enough for the
 * strong-CAS contract here.
 *
 * Auth-code ciphertext is stored verbatim — encryption is the domain's
 * job (see `domain/authorize.ts` → `encryptPayload`), so the adapter
 * never sees plaintext. Inspecting the internal map shows whatever
 * blob the domain saved.
 */
import type { KeyStore } from "../../ports/key-store"
import type { TokenStore } from "../../ports/token-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantId } from "../../types/tenant"
import type { RefreshTokenPayload } from "../../types/token"

import type { Clock } from "./clock"
import { realClock } from "./clock"

const AUTH_CODE_MAX_TTL_MS = 60_000

type StoredCode = {
  ciphertext: string
  expiresAt: number
}

type StoredRefresh = {
  payload: RefreshTokenPayload
  consumedAt?: number
}

export type MemoryTokenStoreOptions = {
  /**
   * Optional — retained for API stability after M1 moved code-payload
   * encryption to the domain layer. The adapter no longer touches it.
   */
  keyStore?: KeyStore
  clock?: Clock
}

export class MemoryTokenStore implements TokenStore {
  #clock: Clock
  #codes = new Map<string, StoredCode>()
  #refresh = new Map<string, StoredRefresh>()

  constructor(opts: MemoryTokenStoreOptions = {}) {
    this.#clock = opts.clock ?? realClock
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
    this.#codes.set(code, { ciphertext, expiresAt: this.#clock() + ttl })
    return ok(undefined)
  }

  async consumeCode(code: string): Promise<Result<string>> {
    const stored = this.#codes.get(code)
    if (!stored) {
      return err(
        authError.invalidGrant("auth code unknown or already consumed"),
      )
    }
    // Atomic delete-on-read: remove **before** returning so a concurrent
    // caller cannot observe the same row.
    this.#codes.delete(code)
    if (this.#clock() >= stored.expiresAt) {
      return err(authError.invalidGrant("auth code expired"))
    }
    return ok(stored.ciphertext)
  }

  async saveRefresh(
    refresh: string,
    payload: RefreshTokenPayload,
  ): Promise<Result<void>> {
    this.#refresh.set(refresh, { payload })
    return ok(undefined)
  }

  async consumeRefresh(
    refresh: string,
    options: { reuseWindowMs?: number } = {},
  ): Promise<Result<RefreshTokenPayload>> {
    const reuseWindow = options.reuseWindowMs ?? 60_000
    const now = this.#clock()
    const stored = this.#refresh.get(refresh)
    if (!stored) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (stored.consumedAt !== undefined) {
      const withinWindow = now - stored.consumedAt <= reuseWindow
      if (withinWindow) {
        // Reuse detection — auto-revoke the family so every descendant of
        // the compromised chain is invalidated. The caller still gets
        // `invalid_grant`; the structured `reuseSignal` carries the
        // family / tenant / subject for audit-log enrichment (port
        // contract per `ports/token-store.ts`).
        const family = stored.payload.family
        await this.revokeFamily(family)
        return err(
          authError.invalidGrant(
            `refresh token reuse detected (family=${family})`,
            {
              family,
              tenantId: stored.payload.tenantId,
              subjectId: stored.payload.subjectId,
            },
          ),
        )
      }
      return err(authError.invalidGrant("refresh token already consumed"))
    }
    if (now >= stored.payload.expiresAt) {
      return err(authError.invalidGrant("refresh token expired"))
    }
    stored.consumedAt = now
    return ok(stored.payload)
  }

  async peekRefresh(
    refresh: string,
  ): Promise<Result<RefreshTokenPayload>> {
    const stored = this.#refresh.get(refresh)
    if (!stored) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (this.#clock() >= stored.payload.expiresAt) {
      return err(authError.invalidGrant("refresh token expired"))
    }
    return ok(stored.payload)
  }

  async revokeFamily(family: string): Promise<Result<void>> {
    for (const [token, stored] of this.#refresh) {
      if (stored.payload.family === family) {
        this.#refresh.delete(token)
      }
    }
    return ok(undefined)
  }

  async revokeBySubject(
    tenantId: TenantId,
    subjectId: string,
  ): Promise<Result<void>> {
    for (const [token, stored] of this.#refresh) {
      if (
        stored.payload.tenantId === tenantId &&
        stored.payload.subjectId === subjectId
      ) {
        this.#refresh.delete(token)
      }
    }
    return ok(undefined)
  }
}
