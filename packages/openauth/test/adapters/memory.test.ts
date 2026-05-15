/**
 * In-memory adapter tests.
 *
 * Each port runs through the parameterized conformance suite in
 * `test/ports/`. Memory-specific behaviour (audit-log `byKind` filter) lives
 * in narrow follow-up cases below.
 */
import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemoryMethodStore,
  MemoryPasskeyCredentialStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"

import {
  describeAuditLog,
  describeConfigStore,
  describeKeyStore,
  describeMethodStore,
  describePasskeyCredentialStore,
  describeSessionStore,
  describeTokenStore,
} from "../ports"

// --- Conformance suite -------------------------------------------------

describeTokenStore({
  adapterName: "memory",
  async makeStore(clock) {
    const keyStore = new MemoryKeyStore({ clock: clock.now })
    const tokenStore = new MemoryTokenStore({ clock: clock.now })
    return {
      tokenStore,
      keyStore,
      // The memory adapter holds the ciphertext on a private map; the
      // round-trip assertion in the conformance suite already exercises
      // verbatim-storage so we don't need a custom raw inspector.
    }
  },
})

describeSessionStore({
  adapterName: "memory",
  supportsLongLivedSessions: true,
  supportsPar: true,
  supportsScratch: true,
  async makeStore(clock) {
    return {
      store: new MemorySessionStore({ clock: clock.now }),
    }
  },
})

describeKeyStore({
  adapterName: "memory",
  async makeStore(clock) {
    return { store: new MemoryKeyStore({ clock: clock.now }) }
  },
})

describeConfigStore({
  adapterName: "memory",
  async makeStore() {
    return { store: new MemoryConfigStore() }
  },
})

describeMethodStore({
  adapterName: "memory",
  async makeStore() {
    return { store: new MemoryMethodStore() }
  },
})

describePasskeyCredentialStore({
  adapterName: "memory",
  async makeStore() {
    return { store: new MemoryPasskeyCredentialStore() }
  },
})

describeAuditLog({
  adapterName: "memory",
  async makeLog() {
    const log = new MemoryAuditLog()
    return {
      log,
      async readEvents() {
        return log.events
      },
    }
  },
})

// --- Memory-only assertions ------------------------------------------

describe("MemoryAuditLog — byKind filter", () => {
  test("filters events of a single kind", async () => {
    const log = new MemoryAuditLog()
    await log.log({
      kind: "authorize_started",
      tenantId: "acme" as never,
      clientId: "rp",
      methodId: "m",
      methodKind: "k",
      flowId: "f",
      timestamp: 1,
    })
    await log.log({
      kind: "token_issued",
      tenantId: "acme" as never,
      clientId: "rp",
      methodId: "m",
      methodKind: "k",
      subjectId: "s",
      timestamp: 2,
    })
    expect(log.byKind("authorize_started").length).toBe(1)
    expect(log.byKind("token_issued").length).toBe(1)
    expect(log.byKind("refresh_reuse_detected").length).toBe(0)
  })
})
