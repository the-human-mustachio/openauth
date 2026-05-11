/**
 * Postgres schema for the IdP adapters. One migration; future schema changes
 * append new migrations and a small migrate-from-version routine.
 *
 * Tables are prefixed `openauth_` so the IdP can share a database with the
 * application that consumes it. The schema is intentionally narrow — JSONB
 * blobs carry the bulk of the data (auth-code ciphertext, refresh payload,
 * tenant config) so that adding fields in later phases is non-breaking.
 *
 * Timestamps are `bigint` (epoch ms) rather than `timestamptz` so that the
 * adapter's injectable clock works seamlessly in tests and so that
 * comparisons are simple integer math.
 */
import type { PostgresExecutor } from "./executor"

export const INITIAL_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS openauth_tenants (
  id text PRIMARY KEY,
  config jsonb NOT NULL,
  updated_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openauth_methods (
  tenant_id text NOT NULL,
  method_id text NOT NULL,
  config jsonb NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (tenant_id, method_id)
);

CREATE TABLE IF NOT EXISTS openauth_signing_keys (
  kid text PRIMARY KEY,
  alg text NOT NULL,
  crv text,
  public_jwk jsonb NOT NULL,
  private_jwk jsonb NOT NULL,
  status text NOT NULL,
  created_at bigint NOT NULL,
  rotated_at bigint
);

CREATE TABLE IF NOT EXISTS openauth_encryption_keys (
  kid text PRIMARY KEY,
  alg text NOT NULL,
  key_material bytea NOT NULL,
  status text NOT NULL,
  created_at bigint NOT NULL,
  rotated_at bigint
);

CREATE TABLE IF NOT EXISTS openauth_codes (
  code text PRIMARY KEY,
  ciphertext text NOT NULL,
  expires_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openauth_refresh_tokens (
  token text PRIMARY KEY,
  tenant_id text NOT NULL,
  client_id text NOT NULL,
  subject_id text NOT NULL,
  family text NOT NULL,
  expires_at bigint NOT NULL,
  consumed_at bigint,
  payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS openauth_refresh_family_idx
  ON openauth_refresh_tokens (family);
CREATE INDEX IF NOT EXISTS openauth_refresh_subject_idx
  ON openauth_refresh_tokens (tenant_id, subject_id);

CREATE TABLE IF NOT EXISTS openauth_flows (
  flow_id text PRIMARY KEY,
  payload jsonb NOT NULL,
  expires_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openauth_sessions (
  session_id text PRIMARY KEY,
  payload jsonb NOT NULL,
  expires_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openauth_audit_events (
  id bigserial PRIMARY KEY,
  ts bigint NOT NULL,
  kind text NOT NULL,
  payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS openauth_audit_kind_idx
  ON openauth_audit_events (kind);
CREATE INDEX IF NOT EXISTS openauth_audit_ts_idx
  ON openauth_audit_events (ts);

CREATE TABLE IF NOT EXISTS openauth_passkey_credentials (
  tenant_id text NOT NULL,
  credential_id text NOT NULL,
  user_id text NOT NULL,
  public_key text NOT NULL,
  counter bigint NOT NULL DEFAULT 0,
  transports jsonb,
  created_at bigint NOT NULL,
  PRIMARY KEY (tenant_id, credential_id)
);
CREATE INDEX IF NOT EXISTS openauth_passkey_user_idx
  ON openauth_passkey_credentials (tenant_id, user_id);
`

/**
 * Apply the initial schema. Idempotent — uses `CREATE TABLE IF NOT EXISTS`.
 * Deployments using a real migration tool can apply the SQL above directly
 * and skip this helper.
 */
export async function migrate(exec: PostgresExecutor): Promise<void> {
  // Some drivers reject a single multi-statement string; PGlite accepts it.
  // Split on the blank line separator + semicolon to handle either case.
  const statements = INITIAL_SCHEMA_SQL.split(/;\s*\n/).filter(
    (s) => s.trim().length > 0,
  )
  for (const stmt of statements) {
    await exec.query(stmt + ";")
  }
}
