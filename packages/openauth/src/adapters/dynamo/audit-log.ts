/**
 * DynamoDB `AuditLog`. `pk="audit"`, `sk="<paddedTs>:<rand>"` so a Query
 * pulls events in insertion order. As with all `AuditLog` adapters, `log()`
 * never throws — durability failures are swallowed so the IdP's hot paths
 * are not gated on the log.
 */
import type { AuditEvent, AuditLog } from "../../ports/audit-log"

import type { DynamoExecutor } from "./client"

export type DynamoAuditLogOptions = {
  exec: DynamoExecutor
}

export class DynamoAuditLog implements AuditLog {
  #exec: DynamoExecutor

  constructor(opts: DynamoAuditLogOptions) {
    this.#exec = opts.exec
  }

  async log(event: AuditEvent & { timestamp: number }): Promise<void> {
    const padded = String(event.timestamp).padStart(16, "0")
    const suffix = Math.random().toString(36).slice(2, 10)
    try {
      await this.#exec.put({
        item: {
          pk: "audit",
          sk: `${padded}:${suffix}`,
          payload: JSON.stringify(event),
        },
      })
    } catch {}
  }
}
