/**
 * Shared `safeAudit` helper — every domain module that emits audit
 * events used to keep its own private `audit(...)` wrapper around
 * `auditLog.log(event)` that silently swallowed any thrown error. The
 * intent (per `ports/audit-log.ts`) is that audit emission must not
 * derail the OAuth hot path, but operators have no signal when the
 * pipeline goes down.
 *
 * Until the Logger port lands in Phase 8, durability failures here
 * surface via `console.error` with a discriminating prefix. The Logger
 * port will replace this single helper — the call sites stay put.
 */
import type { AuditLog } from "../ports/audit-log"

export async function safeAudit(
  deps: { auditLog?: AuditLog },
  event: Parameters<AuditLog["log"]>[0],
): Promise<void> {
  if (!deps.auditLog) return
  try {
    await deps.auditLog.log(event)
  } catch (e) {
    console.error(
      `[openauth] auditLog.log failed for kind=${event.kind} — audit gap; check your AuditLog adapter health`,
      e,
    )
  }
}
