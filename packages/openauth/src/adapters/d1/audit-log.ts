/**
 * D1 `AuditLog`. Append-only inserts; D1's autoincrement provides the
 * insertion order index for SIEM queries. Per `ports/audit-log.ts`, `log()`
 * never throws — durability failures are swallowed because the hot OAuth
 * paths cannot be gated on the audit log.
 */
import type { AuditEvent, AuditLog } from "../../ports/audit-log"

import type { AnyD1Database } from "./types"

export type D1AuditLogOptions = {
  db: AnyD1Database
}

export class D1AuditLog implements AuditLog {
  #db: AnyD1Database

  constructor(opts: D1AuditLogOptions) {
    this.#db = opts.db
  }

  async log(event: AuditEvent & { timestamp: number }): Promise<void> {
    try {
      await this.#db
        .prepare(
          `INSERT INTO openauth_audit_events (ts, kind, payload) VALUES (?1, ?2, ?3)`,
        )
        .bind(event.timestamp, event.kind, JSON.stringify(event))
        .run()
    } catch {}
  }
}
