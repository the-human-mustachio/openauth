/**
 * Durable Objects `SessionStore` conformance.
 *
 * Runs the parameterized SessionStore suite against an in-process
 * `DurableObjectStorage` shim. The shim serializes transactions so the
 * single-winner guarantee under concurrent `consumeFlow` calls is exactly
 * the guarantee a real DO instance provides.
 */
import { DurableObjectSessionStore } from "../../src/adapters/durable-object"

import { createDOStorageShim } from "../helpers/do-storage-shim"
import { describeSessionStore } from "../ports"

describeSessionStore({
  adapterName: "durable-object (in-process)",
  supportsLongLivedSessions: true,
  supportsScratch: true,
  async makeStore(clock) {
    const storage = createDOStorageShim()
    return {
      store: new DurableObjectSessionStore({ storage, clock: clock.now }),
    }
  },
})
