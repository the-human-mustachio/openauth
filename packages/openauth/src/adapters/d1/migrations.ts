/**
 * D1 / SQLite schema for the IdP adapters. Mirrors the Postgres schema
 * exactly with SQLite-flavored types (TEXT for JSON, BLOB for bytes,
 * INTEGER for timestamps and serials).
 *
 * The auth-code payload is encrypted at rest by the adapter before the
 * ciphertext lands in `openauth_codes.ciphertext` — the DB only ever sees
 * the JWE compact string.
 */
import type { AnyD1Database } from "./types"

export const INITIAL_SCHEMA_SQL = [
  `CREATE TABLE IF NOT EXISTS openauth_tenants (
    id TEXT PRIMARY KEY,
    config TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_methods (
    tenant_id TEXT NOT NULL,
    method_id TEXT NOT NULL,
    config TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, method_id)
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    crv TEXT,
    public_jwk TEXT NOT NULL,
    private_jwk TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_encryption_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    key_material BLOB NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_codes (
    code TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_refresh_tokens (
    token TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    family TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    payload TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS openauth_refresh_family_idx ON openauth_refresh_tokens (family)`,
  `CREATE INDEX IF NOT EXISTS openauth_refresh_subject_idx ON openauth_refresh_tokens (tenant_id, subject_id)`,
  `CREATE TABLE IF NOT EXISTS openauth_flows (
    flow_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_sessions (
    session_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_scratch (
    scratch_key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS openauth_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS openauth_audit_kind_idx ON openauth_audit_events (kind)`,
  `CREATE INDEX IF NOT EXISTS openauth_audit_ts_idx ON openauth_audit_events (ts)`,
]

/**
 * Apply the initial schema to a D1 database. Idempotent — every statement
 * is `CREATE … IF NOT EXISTS`. Deployments using `wrangler d1 migrations
 * apply` can apply the SQL above directly.
 */
export async function migrate(db: AnyD1Database): Promise<void> {
  for (const stmt of INITIAL_SCHEMA_SQL) {
    await db.prepare(stmt).run()
  }
}
