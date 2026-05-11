/**
 * DynamoDB adapter conformance.
 *
 * Runs the full port-conformance suite against an in-memory `DynamoExecutor`
 * shim that faithfully implements the subset of DynamoDB semantics the
 * adapter exercises (strong reads, atomic delete-on-read, conditional
 * update, GSIs). The same `DynamoExecutor` shape is satisfied by
 * `fromDynamoDBClient(docClient, tableName)` in production, so passing here
 * is evidence the contract holds on real DynamoDB.
 */
import { beforeEach } from "bun:test"

import {
  DynamoAuditLog,
  DynamoConfigStore,
  DynamoKeyStore,
  DynamoMethodStore,
  DynamoPasskeyCredentialStore,
  DynamoSessionStore,
  DynamoTokenStore,
} from "../../src/adapters/dynamo"

import { createDynamoShim } from "../helpers/dynamo-shim"
import {
  describeAuditLog,
  describeConfigStore,
  describeKeyStore,
  describeMethodStore,
  describePasskeyCredentialStore,
  describeSessionStore,
  describeTokenStore,
} from "../ports"

// One executor per file; each beforeEach clears it.
let exec = createDynamoShim()
beforeEach(() => {
  exec = createDynamoShim()
})

describeTokenStore({
  adapterName: "dynamo (in-memory)",
  async makeStore(clock) {
    const keyStore = new DynamoKeyStore({ exec, clock: clock.now })
    const tokenStore = new DynamoTokenStore({ exec, keyStore, clock: clock.now })
    return {
      tokenStore,
      keyStore,
      async inspectRawCode(code: string) {
        const row = await exec.get({
          key: { pk: "code", sk: code },
          consistentRead: true,
        })
        return row?.ciphertext ? String(row.ciphertext) : ""
      },
    }
  },
})

describeSessionStore({
  adapterName: "dynamo (in-memory)",
  supportsLongLivedSessions: true,
  async makeStore(clock) {
    return { store: new DynamoSessionStore({ exec, clock: clock.now }) }
  },
})

describeKeyStore({
  adapterName: "dynamo (in-memory)",
  async makeStore(clock) {
    return { store: new DynamoKeyStore({ exec, clock: clock.now }) }
  },
})

describeConfigStore({
  adapterName: "dynamo (in-memory)",
  async makeStore() {
    return { store: new DynamoConfigStore({ exec }) }
  },
})

describePasskeyCredentialStore({
  adapterName: "dynamo (in-memory)",
  async makeStore() {
    return { store: new DynamoPasskeyCredentialStore({ exec }) }
  },
})

describeMethodStore({
  adapterName: "dynamo (in-memory)",
  async makeStore() {
    return { store: new DynamoMethodStore({ exec }) }
  },
})

describeAuditLog({
  adapterName: "dynamo (in-memory)",
  async makeLog() {
    const log = new DynamoAuditLog({ exec })
    return {
      log,
      async readEvents() {
        const items = await exec.query({
          pk: "audit",
          consistentRead: true,
        })
        return items.map((r) => JSON.parse(String(r.payload)))
      },
    }
  },
})
