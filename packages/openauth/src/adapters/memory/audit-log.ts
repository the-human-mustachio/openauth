/**
 * In-memory `AuditLog`. Stores events in an array that tests can inspect.
 * Production deployments use a real backend (Clickhouse, OTEL, etc.).
 */
import type { AuditEvent, AuditLog } from "../../ports/audit-log"

export type StoredAuditEvent = AuditEvent & { timestamp: number }

export class MemoryAuditLog implements AuditLog {
  events: StoredAuditEvent[] = []

  async log(event: StoredAuditEvent): Promise<void> {
    this.events.push(event)
  }

  /** Test helper — find events of a given kind. */
  byKind<K extends AuditEvent["kind"]>(
    kind: K,
  ): Array<Extract<StoredAuditEvent, { kind: K }>> {
    return this.events.filter((e) => e.kind === kind) as Array<
      Extract<StoredAuditEvent, { kind: K }>
    >
  }

  clear(): void {
    this.events = []
  }
}
