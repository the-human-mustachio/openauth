/**
 * D1 adapter tests — runs the port-conformance suite against a `bun:sqlite`-
 * backed `D1Database` shim. The Sessions API isn't exposed by the shim, so
 * the adapter's `primarySession` helper feature-detects and falls back to
 * plain `prepare` — exactly the path production runtimes that lack Sessions
 * exercise.
 */
import { D1Database } from "@cloudflare/workers-types"
import { afterAll, beforeAll, beforeEach } from "bun:test"

import {
  D1AuditLog,
  D1ConfigStore,
  D1KeyStore,
  D1MethodStore,
  D1SessionStore,
  D1TokenStore,
  migrate,
} from "../../src/adapters/d1"

import { createD1Shim } from "../helpers/d1-shim"
import {
  describeAuditLog,
  describeConfigStore,
  describeKeyStore,
  describeMethodStore,
  describeSessionStore,
  describeTokenStore,
} from "../ports"

let db: D1Database

beforeAll(async () => {
  db = createD1Shim()
  await migrate(db)
})

afterAll(async () => {
  // bun:sqlite :memory: is GC'd with the shim.
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
  "openauth_scratch",
  "openauth_audit_events",
]

beforeEach(async () => {
  for (const t of TABLES) {
    await db.prepare(`DELETE FROM ${t}`).run()
  }
})

// --- Conformance suite -------------------------------------------------

describeTokenStore({
  adapterName: "d1 (bun:sqlite)",
  async makeStore(clock) {
    const keyStore = new D1KeyStore({ db, clock: clock.now })
    const tokenStore = new D1TokenStore({ db, keyStore, clock: clock.now })
    return {
      tokenStore,
      keyStore,
      async inspectRawCode(code: string) {
        const row = await db
          .prepare(`SELECT ciphertext FROM openauth_codes WHERE code = ?1`)
          .bind(code)
          .first<{ ciphertext: string }>()
        return row?.ciphertext ?? ""
      },
    }
  },
})

describeSessionStore({
  adapterName: "d1 (bun:sqlite)",
  supportsLongLivedSessions: true,
  supportsScratch: true,
  async makeStore(clock) {
    return { store: new D1SessionStore({ db, clock: clock.now }) }
  },
})

describeKeyStore({
  adapterName: "d1 (bun:sqlite)",
  async makeStore(clock) {
    return { store: new D1KeyStore({ db, clock: clock.now }) }
  },
})

describeConfigStore({
  adapterName: "d1 (bun:sqlite)",
  async makeStore() {
    return { store: new D1ConfigStore({ db }) }
  },
})

describeMethodStore({
  adapterName: "d1 (bun:sqlite)",
  async makeStore() {
    return { store: new D1MethodStore({ db }) }
  },
})

describeAuditLog({
  adapterName: "d1 (bun:sqlite)",
  async makeLog() {
    const log = new D1AuditLog({ db })
    return {
      log,
      async readEvents() {
        const result = await db
          .prepare(`SELECT payload FROM openauth_audit_events ORDER BY id`)
          .all<{ payload: string }>()
        return result.results.map((r) => JSON.parse(r.payload))
      },
    }
  },
})
