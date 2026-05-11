/**
 * DynamoDB `TokenStore`. Single-table design (`pk` / `sk` primary key,
 * `family-index` and `subject-index` GSIs).
 *
 * Per `ports/CONSISTENCY.md`:
 *   - All `get`s use `consistentRead: true` — the default eventual-read
 *     would violate the auth-code / refresh-token contracts.
 *   - All `delete`s use `ReturnValues=ALL_OLD` so atomic delete-on-read is
 *     a single round trip.
 *   - `consumeRefresh` uses a conditional `UpdateItem` with
 *     `attribute_not_exists(consumed_at)` so concurrent presentations
 *     resolve to one winner.
 *
 * Layout:
 *   - `pk="code"`,    `sk=<code>`    — auth-code envelope (encrypted-at-rest).
 *   - `pk="refresh"`, `sk=<token>`   — refresh token + JSON payload.
 *       GSI `family-index`:  hash = `family`
 *       GSI `subject-index`: hash = `subject_key` (`<tenant>#<subject>`)
 */
import { decryptPayload, encryptPayload } from "../../domain/crypto"
import type { KeyStore } from "../../ports/key-store"
import type { TokenStore } from "../../ports/token-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, isErr, ok } from "../../types/result"
import type { TenantId } from "../../types/tenant"
import type { CodePayload, RefreshTokenPayload } from "../../types/token"

import type { DynamoExecutor } from "./client"

const AUTH_CODE_MAX_TTL_MS = 60_000

export type DynamoTokenStoreOptions = {
  exec: DynamoExecutor
  keyStore: KeyStore
  clock?: () => number
}

export class DynamoTokenStore implements TokenStore {
  #exec: DynamoExecutor
  #keyStore: KeyStore
  #clock: () => number

  constructor(opts: DynamoTokenStoreOptions) {
    this.#exec = opts.exec
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
    const expiresAtMs = this.#clock() + ttl
    try {
      await this.#exec.put({
        item: {
          pk: "code",
          sk: code,
          ciphertext: jwe,
          expires_at: expiresAtMs,
          // DynamoDB native TTL is in seconds, named conventionally `ttl`.
          // The adapter writes both so operators can enable TTL on the table.
          ttl: Math.floor(expiresAtMs / 1000),
        },
      })
    } catch (e) {
      return err(authError.internalError("saveCode: put failed", e))
    }
    return ok(undefined)
  }

  async consumeCode(code: string): Promise<Result<CodePayload>> {
    let row: Record<string, unknown> | undefined
    try {
      row = await this.#exec.delete({ key: { pk: "code", sk: code } })
    } catch (e) {
      return err(authError.internalError("consumeCode: delete failed", e))
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
      const ciphertext = row.ciphertext as string
      const payload = await decryptPayload<CodePayload>(ciphertext, async (kid) => {
        const r = await this.#keyStore.getEncryptionKey(kid)
        if (isErr(r)) throw new Error(`unknown encryption kid ${kid}`)
        return r.value.keyRef as Uint8Array
      })
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
      await this.#exec.put({
        item: {
          pk: "refresh",
          sk: refresh,
          payload: JSON.stringify(payload),
          family: payload.family,
          subject_key: `${payload.tenantId}#${payload.subjectId}`,
          tenant_id: payload.tenantId,
          subject_id: payload.subjectId,
          expires_at: payload.expiresAt,
          ttl: Math.floor(payload.expiresAt / 1000),
        },
      })
    } catch (e) {
      return err(authError.internalError("saveRefresh: put failed", e))
    }
    return ok(undefined)
  }

  async consumeRefresh(
    refresh: string,
    options: { reuseWindowMs?: number } = {},
  ): Promise<Result<RefreshTokenPayload>> {
    const reuseWindow = options.reuseWindowMs ?? 60_000
    const now = this.#clock()
    let claimed: Record<string, unknown> | null
    try {
      claimed = await this.#exec.consumeRefresh({
        key: { pk: "refresh", sk: refresh },
        now,
      })
    } catch (e) {
      return err(authError.internalError("consumeRefresh: claim failed", e))
    }
    if (claimed) {
      return ok(parseRefresh(claimed.payload))
    }
    // No claim. Look up to disambiguate unknown vs already-consumed vs expired.
    let existing: Record<string, unknown> | undefined
    try {
      existing = await this.#exec.get({
        key: { pk: "refresh", sk: refresh },
        consistentRead: true,
      })
    } catch (e) {
      return err(authError.internalError("consumeRefresh: lookup failed", e))
    }
    if (!existing) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (existing.consumed_at !== undefined && existing.consumed_at !== null) {
      const consumedAt = Number(existing.consumed_at)
      const withinWindow = now - consumedAt <= reuseWindow
      if (withinWindow) {
        const payload = parseRefresh(existing.payload)
        await this.revokeFamily(payload.family)
        return err(
          authError.invalidGrant(
            `refresh token reuse detected (family=${payload.family},tenant=${payload.tenantId},subject=${payload.subjectId})`,
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

  async revokeFamily(family: string): Promise<Result<void>> {
    let items: Record<string, unknown>[]
    try {
      items = await this.#exec.queryByGsi({
        indexName: "family-index",
        hashKey: family,
      })
    } catch (e) {
      return err(authError.internalError("revokeFamily: query failed", e))
    }
    for (const item of items) {
      try {
        await this.#exec.delete({
          key: { pk: String(item.pk), sk: String(item.sk) },
        })
      } catch {
        // Best-effort — a deletion losing a race is acceptable.
      }
    }
    return ok(undefined)
  }

  async revokeBySubject(
    tenantId: TenantId,
    subjectId: string,
  ): Promise<Result<void>> {
    let items: Record<string, unknown>[]
    try {
      items = await this.#exec.queryByGsi({
        indexName: "subject-index",
        hashKey: `${tenantId}#${subjectId}`,
      })
    } catch (e) {
      return err(authError.internalError("revokeBySubject: query failed", e))
    }
    for (const item of items) {
      try {
        await this.#exec.delete({
          key: { pk: String(item.pk), sk: String(item.sk) },
        })
      } catch {}
    }
    return ok(undefined)
  }
}

function parseRefresh(raw: unknown): RefreshTokenPayload {
  if (typeof raw === "string") return JSON.parse(raw) as RefreshTokenPayload
  return raw as RefreshTokenPayload
}
