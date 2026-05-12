/**
 * Parameterized `AuditLog` conformance suite.
 *
 * Adapters that buffer writes must `flush()` before the test reads events
 * back; the `readEvents` callback in the options bundles whatever
 * adapter-specific flush + fetch is needed.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type { AuditEvent, AuditLog } from "../../src/ports/audit-log"

import { fixtureTenantId } from "./fixtures"

export type AuditLogSuiteOptions = {
  adapterName: string
  makeLog: () => Promise<{
    log: AuditLog
    /** Flush + fetch every event written so far. */
    readEvents: () => Promise<Array<AuditEvent & { timestamp: number }>>
    dispose?: () => Promise<void>
  }>
}

export function describeAuditLog(opts: AuditLogSuiteOptions): void {
  describe(`AuditLog conformance — ${opts.adapterName}`, () => {
    let log: AuditLog
    let readEvents: () => Promise<Array<AuditEvent & { timestamp: number }>>
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      const built = await opts.makeLog()
      log = built.log
      readEvents = built.readEvents
      dispose = built.dispose
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    test("log() persists events; readEvents returns them", async () => {
      await log.log({
        kind: "authorize_started",
        tenantId: fixtureTenantId,
        clientId: "rp",
        methodId: "m",
        methodKind: "k",
        flowId: "f",
        timestamp: 100,
      })
      await log.log({
        kind: "token_issued",
        tenantId: fixtureTenantId,
        clientId: "rp",
        methodId: "m",
        methodKind: "k",
        subjectId: "s",
        timestamp: 200,
      })
      const events = await readEvents()
      const kinds = events.map((e) => e.kind).sort()
      expect(kinds).toContain("authorize_started")
      expect(kinds).toContain("token_issued")
    })

    test("preserves payload fields", async () => {
      await log.log({
        kind: "refresh_reuse_detected",
        tenantId: fixtureTenantId,
        clientId: "rp",
        family: "FAM-Z",
        timestamp: 1,
      })
      const events = await readEvents()
      const ev = events.find((e) => e.kind === "refresh_reuse_detected")
      expect(ev).toBeDefined()
      if (ev && ev.kind === "refresh_reuse_detected") {
        expect(ev.family).toBe("FAM-Z")
      }
    })

    test("accepts custom events", async () => {
      await log.log({
        kind: "custom",
        type: "manual_action",
        tenantId: fixtureTenantId,
        data: { user: "admin", action: "purge" },
        timestamp: 5,
      })
      const events = await readEvents()
      const ev = events.find((e) => e.kind === "custom")
      expect(ev).toBeDefined()
    })
  })
}
