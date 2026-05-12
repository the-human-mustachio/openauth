/**
 * Cloudflare KV `AuditLog`. Append-only with per-event keys of the shape
 * `audit:<paddedTs>:<rand>` so KV's lexicographic list returns events in
 * insertion order. Suitable for low-volume audit (the IdP) where reads are
 * SIEM-style after-the-fact, not hot-path. High-volume deployments should
 * ship events out-of-band to a real append-log.
 */
import type { AuditEvent, AuditLog } from "../../ports/audit-log"

import type { KVNamespaceLike } from "./types"

const PREFIX = "audit:"

export type KvAuditLogOptions = {
  kv: KVNamespaceLike
  /** Optional TTL (seconds). 90 days minimum per CONSISTENCY.md SOC 2 baseline. */
  expirationTtl?: number
}

export class KvAuditLog implements AuditLog {
  #kv: KVNamespaceLike
  #ttl: number | undefined

  constructor(opts: KvAuditLogOptions) {
    this.#kv = opts.kv
    this.#ttl = opts.expirationTtl
  }

  async log(event: AuditEvent & { timestamp: number }): Promise<void> {
    const padded = String(event.timestamp).padStart(16, "0")
    const suffix = Math.random().toString(36).slice(2, 10)
    try {
      await this.#kv.put(
        `${PREFIX}${padded}:${suffix}`,
        JSON.stringify(event),
        this.#ttl ? { expirationTtl: this.#ttl } : undefined,
      )
    } catch {}
  }
}
