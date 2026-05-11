/**
 * In-memory `TokenStore`. Single-process; the `Map` operations are
 * atomic with respect to JS event-loop turns, which is enough for the
 * strong-CAS contract here.
 *
 * Encryption-at-rest is real: code payloads are encrypted via JOSE
 * compact-JWE (A256GCM) before being written to the internal map, and
 * decrypted on consume. Direct inspection of the map shows ciphertext.
 */
import type { KeyStore } from "../../ports/key-store"
import type { TokenStore } from "../../ports/token-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, isErr, ok } from "../../types/result"
import type { TenantId } from "../../types/tenant"
import type { CodePayload, RefreshTokenPayload } from "../../types/token"

import { decryptPayload, encryptPayload } from "../../domain/crypto"
import type { Clock } from "./clock"
import { realClock } from "./clock"

const AUTH_CODE_MAX_TTL_MS = 60_000

type StoredCode = {
  jwe: string
  expiresAt: number
}

type StoredRefresh = {
  payload: RefreshTokenPayload
  consumedAt?: number
}

export type MemoryTokenStoreOptions = {
  keyStore: KeyStore
  clock?: Clock
}

export class MemoryTokenStore implements TokenStore {
  #keyStore: KeyStore
  #clock: Clock
  #codes = new Map<string, StoredCode>()
  #refresh = new Map<string, StoredRefresh>()

  constructor(opts: MemoryTokenStoreOptions) {
    this.#keyStore = opts.keyStore
    this.#clock = opts.clock ?? realClock
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
    const keyBytes = keyResult.value.keyRef as Uint8Array
    let jwe: string
    try {
      jwe = await encryptPayload(payload, keyResult.value.kid, keyBytes)
    } catch (e) {
      return err(authError.internalError("saveCode: encrypt failed", e))
    }
    this.#codes.set(code, { jwe, expiresAt: this.#clock() + ttl })
    return ok(undefined)
  }

  async consumeCode(code: string): Promise<Result<CodePayload>> {
    const stored = this.#codes.get(code)
    if (!stored) {
      return err(
        authError.invalidGrant("auth code unknown or already consumed"),
      )
    }
    // Atomic delete-on-read: remove **before** decrypting so a concurrent
    // caller cannot observe the same row.
    this.#codes.delete(code)
    if (this.#clock() >= stored.expiresAt) {
      return err(authError.invalidGrant("auth code expired"))
    }
    let payload: CodePayload
    try {
      payload = await decryptPayload<CodePayload>(stored.jwe, async (kid) => {
        const keyResult = await this.#keyStore.getEncryptionKey(kid)
        if (isErr(keyResult)) {
          throw new Error(`unknown encryption kid ${kid}`)
        }
        return keyResult.value.keyRef as Uint8Array
      })
    } catch (e) {
      return err(authError.internalError("consumeCode: decrypt failed", e))
    }
    return ok(payload)
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
        // Reuse detection — auto-revoke the family so all descendants of
        // the compromised chain are invalidated. The caller still gets
        // `invalid_grant`; the family-id is stashed on the error
        // description for audit-log enrichment.
        const family = stored.payload.family
        await this.revokeFamily(family)
        return err(
          authError.invalidGrant(
            `refresh token reuse detected (family=${family},tenant=${stored.payload.tenantId},subject=${stored.payload.subjectId})`,
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
