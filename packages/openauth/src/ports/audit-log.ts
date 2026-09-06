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
      /** OIDC Core §2 — set when the response carried an `id_token`. */
      idTokenIssued?: boolean
      /** RFC 9449 — set when the access token is DPoP-bound. */
      dpopBound?: boolean
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
       * Emitted after a logout is processed. Two channels, discriminated
       * by `via`:
       *
       *  - `rp_initiated` (or absent — the default): `/end_session`
       *    (OIDC RP-Initiated Logout 1.0 §2), regardless of whether a
       *    `post_logout_redirect_uri` was supplied. `subjectId` present
       *    when an `id_token_hint` verified; absent otherwise.
       *  - `upstream_slo`: an upstream IdP notified us a federated
       *    session ended (SAML front-channel Single Logout). `methodId`
       *    / `methodKind` identify the federation connection;
       *    `subjectId` present only when the host's `onLogout` returned
       *    a subject to revoke.
       *
       * `via` is general (OIDC back-channel logout would reuse
       * `upstream_slo`), not SAML-specific surface.
       */
      kind: "session_logout"
      tenantId: TenantId
      clientId?: string
      subjectId?: string
      via?: "rp_initiated" | "upstream_slo"
      methodId?: string
      methodKind?: string
    }
  | {
      /**
       * Emitted when a DPoP proof's `jti` is presented within the replay
       * window (RFC 9449 §11.1). The request was rejected with
       * `invalid_dpop_proof`. Operators / SIEM use this to spot
       * stolen-key replay attempts.
       */
      kind: "dpop_replay_detected"
      tenantId: TenantId | null
      /** First-half of the offending jti so logs can correlate without storing it. */
      jtiPrefix: string
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
      /**
       * `IdPOptions.success` returned a claim that violates the host's
       * own `subjects` schema. A deployment fault, not RP behaviour —
       * token issuance is refused. Carries paths, never values.
       */
      kind: "invalid_subject_claim"
      tenantId: TenantId
      clientId: string
      subjectType: string
      reason: "unknown-type" | "invalid-properties"
      /** Standard Schema issue path, or the declared type list. */
      detail: string
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
