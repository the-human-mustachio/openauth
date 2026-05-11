/**
 * Cloudflare KV adapter conformance.
 *
 * KV is acceptable for `ConfigStore` / `MethodStore` / `AuditLog` (the
 * read-eventual, low-volume paths). The full conformance suite runs against
 * an in-process KV shim — strict on contract, lax on consistency-window
 * simulation.
 */
import {
  KvAuditLog,
  KvConfigStore,
  KvMethodStore,
} from "../../src/adapters/kv"

import { createKvShim } from "../helpers/kv-shim"
import {
  describeAuditLog,
  describeConfigStore,
  describeMethodStore,
} from "../ports"

describeConfigStore({
  adapterName: "kv (in-process)",
  async makeStore() {
    return { store: new KvConfigStore({ kv: createKvShim() }) }
  },
})

describeMethodStore({
  adapterName: "kv (in-process)",
  async makeStore() {
    return { store: new KvMethodStore({ kv: createKvShim() }) }
  },
})

describeAuditLog({
  adapterName: "kv (in-process)",
  async makeLog() {
    const kv = createKvShim()
    const log = new KvAuditLog({ kv })
    return {
      log,
      async readEvents() {
        const result = await kv.list({ prefix: "audit:" })
        const events: Array<Record<string, unknown>> = []
        for (const k of result.keys) {
          const raw = await kv.get(k.name)
          if (raw) events.push(JSON.parse(raw))
        }
        return events as never
      },
    }
  },
})
