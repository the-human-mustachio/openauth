/**
 * `TokenStore` — authorization codes + refresh tokens.
 *
 * All methods on this port are **security-critical** and require strong,
 * atomic semantics. Cloudflare KV is **not** an acceptable backing store
 * for any method here; use D1 (Sessions API w/ bookmarks), Durable Objects,
 * Postgres (`SELECT FOR UPDATE`), or DynamoDB with conditional writes.
 *
 * See `ports/CONSISTENCY.md` §"Per-method consistency contracts".
 */
import type { RefreshTokenPayload } from "../types/token"
import type { Result } from "../types/result"
import type { TenantId } from "../types/tenant"

export type TokenStore = {
  /**
   * Persist an auth-code ciphertext blob under `code`.
   *
   * The blob is **opaque** to the adapter — the framework encrypts the
   * `CodePayload` at the domain boundary (`domain/authorize.ts` →
   * `domain/crypto.encryptPayload`) before calling `saveCode`. Adapters
   * must not parse, transform, or otherwise interpret the blob; just
   * store it verbatim and return it on `consumeCode`.
   *
   * Required semantics:
   *  - Strong, atomic write (the row must be visible to the next
   *    `consumeCode` call on any node).
   *  - `ttl` must be ≤ the framework's auth-code TTL (60 s).
   *    Implementations that receive a larger value must reject.
   */
  saveCode(code: string, ciphertext: string, ttl: number): Promise<Result<void>>

  /**
   * Single-use, atomic compare-and-swap: return and delete the
   * ciphertext blob in one logical operation. Concurrent calls with the
   * same `code` must resolve to exactly one winner; losers receive
   * `invalid_grant`. The caller (`domain/token.exchangeCode`) decrypts
   * the returned blob.
   */
  consumeCode(code: string): Promise<Result<string>>

  /**
   * Persist a refresh-token payload. Strong, atomic. New tokens issued
   * during rotation must be immediately retrievable.
   */
  saveRefresh(
    refresh: string,
    payload: RefreshTokenPayload,
  ): Promise<Result<void>>

  /**
   * Rotate a refresh token. Strong CAS with reuse-detection window.
   *
   * Implementations must:
   *  - Atomically check the token is unconsumed, mark it consumed, and
   *    return its payload — concurrent presentations of the same token
   *    resolve to exactly one winner.
   *  - Within the reuse window (default 60 s), the consumed token must
   *    still be detectable so a second presentation can trigger
   *    revoke-the-whole-family. Outside the window the row may be GC'd.
   *  - On reuse-detection (second consume within the window), return an
   *    `invalid_grant` error **with a `reuseSignal` carrier** containing
   *    the compromised refresh chain's `family`, `tenantId`, and
   *    `subjectId`. The framework's refresh-grant handler reads
   *    `reuseSignal` directly to emit `refresh_reuse_detected` audit
   *    events. Adapters that omit the signal degrade audit fidelity (the
   *    framework falls back to the peeked-payload values) but remain
   *    behavior-compatible.
   */
  consumeRefresh(
    refresh: string,
    options?: { reuseWindowMs?: number },
  ): Promise<Result<RefreshTokenPayload>>

  /**
   * Non-destructive lookup. Returns the refresh-token payload without
   * marking it consumed.
   *
   * Used by RFC 7009 `/revoke` to enforce token-to-client binding
   * (§2.2) before destructively consuming. Returns `invalid_grant` for
   * unknown or expired tokens; `peekRefresh` does **not** trigger
   * reuse-detection — a token already past `consumeRefresh` is still
   * reported here so the caller can decide whether to escalate.
   *
   * Eventual consistency is acceptable: callers race `peekRefresh` then
   * `consumeRefresh`, and the atomicity guarantees of `consumeRefresh`
   * remain authoritative.
   */
  peekRefresh(refresh: string): Promise<Result<RefreshTokenPayload>>

  /**
   * Revoke all refresh tokens whose `RefreshTokenPayload.family` equals
   * `family`. Used by reuse-detection to invalidate every descendant of a
   * compromised refresh chain.
   */
  revokeFamily(family: string): Promise<Result<void>>

  /**
   * Revoke every refresh token for the given (tenant, subject) pair. Strong
   * preferred; documented eventual lag acceptable.
   */
  revokeBySubject(tenantId: TenantId, subjectId: string): Promise<Result<void>>
}
