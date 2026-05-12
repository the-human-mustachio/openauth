/**
 * Regression for the `updateFlowMethodState` + `consumeFlow` race in
 * `DynamoSessionStore`.
 *
 * Before the fix, the read-modify-write path executed
 *   get → (no guard) → put
 * which let a concurrent `consumeFlow` deletion get clobbered: the put
 * recreated the deleted row, the original caller could re-consume, and
 * flow-reuse detection silently bypassed.
 *
 * The adapter now passes `condition: "exists"` so the put fails with
 * `ConditionalCheckFailedException`, which the adapter translates into a
 * typed `unknown_state` failure.
 */
import { describe, expect, test } from "bun:test"

import { DynamoSessionStore } from "../../src/adapters/dynamo"
import type { DynamoExecutor } from "../../src/adapters/dynamo/client"

import { createDynamoShim } from "../helpers/dynamo-shim"
import { makeFlow } from "../ports/fixtures"

/**
 * Wrap a shim executor so that the first `get` triggers a `delete` on the
 * same key after returning the row — simulating a concurrent `consumeFlow`
 * landing between the adapter's `get` and its follow-up `put`.
 */
function withRaceOnGet(exec: DynamoExecutor): DynamoExecutor {
  let raced = false
  return {
    ...exec,
    async get(input) {
      const row = await exec.get(input)
      if (!raced && row) {
        raced = true
        await exec.delete({ key: input.key })
      }
      return row
    },
  }
}

describe("DynamoSessionStore.updateFlowMethodState — concurrent consume race", () => {
  test("update fails with unknown_state instead of resurrecting the deleted row", async () => {
    const exec = createDynamoShim()
    const flow = makeFlow({ flowId: "race-1" })
    const store = new DynamoSessionStore({ exec })
    const save = await store.saveFlow(flow.flowId, flow, 10 * 60 * 1000)
    expect(save.ok).toBe(true)

    // Inject the race only into the update path.
    const racing = new DynamoSessionStore({ exec: withRaceOnGet(exec) })
    const updated = await racing.updateFlowMethodState(flow.flowId, {
      upstreamPkceVerifier: "v-1",
    })
    expect(updated.ok).toBe(false)
    if (!updated.ok) expect(updated.error.code).toBe("unknown_state")

    // The row stays deleted — a follow-up consume cannot resurrect it.
    const consumed = await store.consumeFlow(flow.flowId)
    expect(consumed.ok).toBe(false)
    if (!consumed.ok) expect(consumed.error.code).toBe("unknown_state")

    // And nothing remains in the table under the flow pk.
    const remaining = await exec.query({ pk: "flow", consistentRead: true })
    expect(remaining.length).toBe(0)
  })
})
