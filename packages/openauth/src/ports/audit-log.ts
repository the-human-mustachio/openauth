/**
 * `AuditLog` — append-only event log for security-relevant operations.
 *
 * Consistency: append-only, durable. Ordering across instances is **not**
 * required; consumers (SIEM, dashboards) sort by `timestamp` and `actor`.
 *
 * Retention: defined by the adapter. 90 days minimum is the documented
 * baseline for SOC 2 readiness.
 *
 * Audit-event payloads must **never** contain auth-code payloads, refresh
 * tokens, access tokens, raw cookies, or any other secret. The framework's
 * built-in events follow this rule; custom emitters must too.
 */
import type { TenantId } from "../types/tenant"

/**
 * Discriminated event union. The framework emits these; user code may emit
 * its own with `kind: "custom"`. Each event carries enough id information
 * for operators to find the offending record without exposing secrets.
 */
export type AuditEvent =
  | {
      kind: "authorize_started"
      tenantId: TenantId
      clientId: string
      methodId: string
      methodKind: string
      flowId: string
    }
  | {
      kind: "authorize_succeeded"
      tenantId: TenantId
      clientId: string
      methodId: string
      methodKind: string
      flowId: string
      subjectId: string
    }
  | {
      kind: "authorize_failed"
      tenantId: TenantId | null
      clientId: string | null
      methodId?: string
      methodKind?: string
      flowId?: string
      reason: string
    }
  | {
      kind: "token_issued"
      tenantId: TenantId
      clientId: string
      methodId: string
      methodKind: string
      subjectId: string
      /** Hash of the issued refresh token id — never the token itself. */
      refreshTokenIdHash?: string
    }
  | {
      kind: "token_refreshed"
      tenantId: TenantId
      clientId: string
      subjectId: string
      family: string
    }
  | {
      kind: "token_exchanged"
      /** Tenant the new tokens are scoped to. */
      tenantId: TenantId
      /** Tenant the subject_token was originally issued for. */
      fromTenantId: TenantId
      clientId: string
      subjectId: string
      /** Fresh refresh-token family for the issued tokens. */
      family: string
    }
  | {
      kind: "token_revoked"
      tenantId: TenantId
      clientId: string | null
      subjectId?: string
      family?: string
      reason: string
    }
  | {
      kind: "refresh_reuse_detected"
      tenantId: TenantId
      clientId: string
      family: string
    }
  | {
      /**
       * Emitted by `/end_session` (OIDC RP-Initiated Logout 1.0 §2) after
       * processing the logout request — regardless of whether a
       * `post_logout_redirect_uri` was supplied. `subjectId` is present
       * when the request carried an `id_token_hint` that successfully
       * verified; absent otherwise.
       */
      kind: "session_logout"
      tenantId: TenantId
      clientId?: string
      subjectId?: string
    }
  | {
      kind: "flow_replay_attempt"
      tenantId: TenantId | null
      flowId: string
    }
  | {
      kind: "flow_tenant_mismatch"
      stateTenantId: TenantId
      flowTenantId: TenantId
      flowId: string
    }
  | {
      kind: "flow_callback_mismatch"
      tenantId: TenantId
      flowId: string
      expected: { host: string; path: string }
      actual: { host: string; path: string }
    }
  | {
      kind: "factory_id_mismatch"
      tenantId: TenantId
      methodId: string
      expectedKind: string
      actualKind: string
    }
  | {
      kind: "invalid_method_config"
      tenantId: TenantId
      methodId: string
      methodKind: string
      /** Zod error path string. Never the raw config blob. */
      errorPath: string
    }
  | {
      kind: "unknown_method_kind"
      tenantId: TenantId
      methodId: string
      methodKind: string
    }
  | {
      kind: "unrecoverable_flow"
      reason: string
      host?: string
    }
  | {
      kind: "custom"
      type: string
      tenantId?: TenantId
      data: Record<string, unknown>
    }

export type AuditLog = {
  /**
   * Append a single event. Should not throw on durability failure; the
   * adapter is responsible for buffering / retry. Returning never-rejects
   * is acceptable so the IdP's hot paths are not gated on the log.
   */
  log(event: AuditEvent & { timestamp: number }): Promise<void>
}
