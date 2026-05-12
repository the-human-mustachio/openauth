import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test"

import { safeAudit } from "../../src/domain/audit"
import type { AuditLog } from "../../src/ports/audit-log"
import { fixtureTenantId } from "../ports/fixtures"

const event = {
  kind: "token_issued",
  tenantId: fixtureTenantId,
  clientId: "rp-1",
  methodId: "m",
  methodKind: "k",
  subjectId: "s",
  timestamp: 1234,
} as Parameters<AuditLog["log"]>[0]

describe("safeAudit", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let errSpy: any
  beforeEach(() => {
    errSpy = mock(() => {})
    console.error = errSpy
  })
  afterEach(() => {
    errSpy.mockClear()
  })

  test("no-op when deps.auditLog is absent", async () => {
    await safeAudit({}, event)
    expect(errSpy).not.toHaveBeenCalled()
  })

  test("logs successfully — no console.error", async () => {
    const log = mock(async () => {})
    await safeAudit({ auditLog: { log } as unknown as AuditLog }, event)
    expect(log).toHaveBeenCalledTimes(1)
    expect(errSpy).not.toHaveBeenCalled()
  })

  test("console.error on adapter failure, includes the event kind", async () => {
    const log = mock(async () => {
      throw new Error("dynamo down")
    })
    await safeAudit({ auditLog: { log } as unknown as AuditLog }, event)
    expect(errSpy).toHaveBeenCalledTimes(1)
    const msg = errSpy.mock.calls[0][0] as string
    expect(msg).toContain("kind=token_issued")
    expect(msg).toContain("audit gap")
  })
})
