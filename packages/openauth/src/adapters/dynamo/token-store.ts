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
 *   - `pk="code"`,    `sk=<code>`    — auth-code ciphertext blob (the
 *       domain encrypts before saveCode; the adapter stores verbatim).
 *   - `pk="refresh"`, `sk=<token>`   — refresh token + JSON payload.
 *       GSI `family-index`:  hash = `family`
 *       GSI `subject-index`: hash = `subject_key` (`<tenant>#<subject>`)
 */
import type { KeyStore } from "../../ports/key-store"
import type { TokenStore } from "../../ports/token-store"
import { authError } from "../../types/error"
import type { Result } from "../../types/result"
import { err, ok } from "../../types/result"
import type { TenantId } from "../../types/tenant"
import type { RefreshTokenPayload } from "../../types/token"

import type { DynamoExecutor } from "./client"

const AUTH_CODE_MAX_TTL_MS = 60_000

export type DynamoTokenStoreOptions = {
  exec: DynamoExecutor
  /**
   * Optional — retained for API stability after M1 moved code-payload
   * encryption to the domain layer. The adapter no longer touches it.
   */
  keyStore?: KeyStore
  clock?: () => number
}

export class DynamoTokenStore implements TokenStore {
  #exec: DynamoExecutor
  #clock: () => number

  constructor(opts: DynamoTokenStoreOptions) {
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
    const expiresAtMs = this.#clock() + ttl
    try {
      await this.#exec.put({
        item: {
          pk: "code",
          sk: code,
          ciphertext,
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

  async consumeCode(code: string): Promise<Result<string>> {
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
    return ok(String(row.ciphertext))
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
    let existing: Record<string, unknown> | undefined
    try {
      existing = await this.#exec.get({
        key: { pk: "refresh", sk: refresh },
        consistentRead: true,
      })
    } catch (e) {
      return err(authError.internalError("peekRefresh: lookup failed", e))
    }
    if (!existing) {
      return err(authError.invalidGrant("refresh token unknown"))
    }
    if (this.#clock() >= Number(existing.expires_at)) {
      return err(authError.invalidGrant("refresh token expired"))
    }
    return ok(parseRefresh(existing.payload))
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
