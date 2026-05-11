/**
 * Postgres adapter tests — runs the parameterized port-conformance suite
 * against `PGlite` (in-process WASM Postgres). No external services or
 * Docker needed.
 *
 * Production deployments wire `fromPostgresJs(sql)` against the porsager
 * driver; the conformance contracts are SQL-identical so passing here is
 * sufficient evidence the adapter satisfies the contract on a real server.
 */
import { PGlite } from "@electric-sql/pglite"
import { afterAll, beforeAll, beforeEach } from "bun:test"

import {
  fromPGlite,
  migrate,
  PostgresAuditLog,
  PostgresConfigStore,
  PostgresKeyStore,
  PostgresMethodStore,
  PostgresSessionStore,
  PostgresTokenStore,
  type PostgresExecutor,
} from "../../src/adapters/postgres"

import {
  describeAuditLog,
  describeConfigStore,
  describeKeyStore,
  describeMethodStore,
  describeSessionStore,
  describeTokenStore,
} from "../ports"

/**
 * One PGlite instance per test file. `beforeEach` truncates every IdP table
 * so cases don't leak state. PGlite is fast enough (~5ms truncate) that this
 * is cheaper than rebooting the instance per test.
 */
let pglite: PGlite
let exec: PostgresExecutor

beforeAll(async () => {
  pglite = new PGlite()
  exec = fromPGlite(pglite)
  await migrate(exec)
})

afterAll(async () => {
  await pglite.close()
})

const TABLES = [
  "openauth_tenants",
  "openauth_methods",
  "openauth_signing_keys",
  "openauth_encryption_keys",
  "openauth_codes",
  "openauth_refresh_tokens",
  "openauth_flows",
  "openauth_sessions",
  "openauth_audit_events",
]

beforeEach(async () => {
  for (const t of TABLES) {
    await exec.query(`TRUNCATE TABLE ${t} CASCADE`)
  }
})

// --- Conformance suite -------------------------------------------------

describeTokenStore({
  adapterName: "postgres (pglite)",
  async makeStore(clock) {
    const keyStore = new PostgresKeyStore({ exec, clock: clock.now })
    const tokenStore = new PostgresTokenStore({
      exec,
      keyStore,
      clock: clock.now,
    })
    return {
      tokenStore,
      keyStore,
      async inspectRawCode(code: string) {
        const result = await exec.query<{ ciphertext: string }>(
          `SELECT ciphertext FROM openauth_codes WHERE code = $1`,
          [code],
        )
        return result.rows[0]?.ciphertext ?? ""
      },
    }
  },
})

describeSessionStore({
  adapterName: "postgres (pglite)",
  supportsLongLivedSessions: true,
  async makeStore(clock) {
    return {
      store: new PostgresSessionStore({ exec, clock: clock.now }),
    }
  },
})

describeKeyStore({
  adapterName: "postgres (pglite)",
  async makeStore(clock) {
    return {
      store: new PostgresKeyStore({ exec, clock: clock.now }),
    }
  },
})

describeConfigStore({
  adapterName: "postgres (pglite)",
  async makeStore() {
    return { store: new PostgresConfigStore({ exec }) }
  },
})

describeMethodStore({
  adapterName: "postgres (pglite)",
  async makeStore() {
    return { store: new PostgresMethodStore({ exec }) }
  },
})

describeAuditLog({
  adapterName: "postgres (pglite)",
  async makeLog() {
    const log = new PostgresAuditLog({ exec })
    return {
      log,
      async readEvents() {
        const result = await exec.query<{ payload: unknown }>(
          `SELECT payload FROM openauth_audit_events ORDER BY id`,
        )
        return result.rows.map((r) => {
          const raw = r.payload
          if (typeof raw === "string") return JSON.parse(raw)
          return raw
        }) as Awaited<ReturnType<NonNullable<Parameters<typeof describeAuditLog>[0]["makeLog"]>>>["readEvents"] extends () => Promise<infer R>
          ? R
          : never
      },
    }
  },
})
