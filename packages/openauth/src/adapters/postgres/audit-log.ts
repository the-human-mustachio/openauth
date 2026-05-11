/**
 * Postgres `AuditLog`. Append-only `openauth_audit_events` table; indexed on
 * `kind` and `ts` for SIEM-style queries. Writes are synchronous — adapters
 * looking for batching can wrap this with their own buffering layer.
 */
import type { AuditEvent, AuditLog } from "../../ports/audit-log"

import type { PostgresExecutor } from "./executor"

export type PostgresAuditLogOptions = {
  exec: PostgresExecutor
}

export class PostgresAuditLog implements AuditLog {
  #exec: PostgresExecutor

  constructor(opts: PostgresAuditLogOptions) {
    this.#exec = opts.exec
  }

  async log(event: AuditEvent & { timestamp: number }): Promise<void> {
    try {
      await this.#exec.query(
        `INSERT INTO openauth_audit_events (ts, kind, payload)
         VALUES ($1, $2, $3::jsonb)`,
        [event.timestamp, event.kind, JSON.stringify(event)],
      )
    } catch {
      // Per `ports/audit-log.ts` JSDoc: `log` should not throw on durability
      // failure. The IdP's hot paths must not be gated on the audit log.
      // Future: add a buffering layer with backoff.
    }
  }
}
