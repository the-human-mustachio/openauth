/**
 * In-process shim for `DurableObjectStorage`. Backed by a `Map` plus a
 * per-instance lock so `transaction` callbacks run serially — matching the
 * single-threaded-per-DO execution model in production.
 *
 * Used by `test/adapters/durable-object.test.ts` so the SessionStore
 * conformance suite runs without spinning up a real Workers runtime.
 */
import type {
  DurableObjectStorageLike,
  DurableObjectTransactionLike,
} from "../../src/adapters/durable-object/types"

export function createDOStorageShim(): DurableObjectStorageLike {
  const map = new Map<string, unknown>()
  // Serialize transactions so callers see DO-style "one at a time on this
  // instance" semantics — without this, two concurrent `consumeFlow` calls
  // could both observe the row before either deletes it.
  let lock: Promise<unknown> = Promise.resolve()

  const txnOps: DurableObjectTransactionLike = {
    async get<T>(key: string) {
      return map.get(key) as T | undefined
    },
    async put<T>(key: string, value: T) {
      map.set(key, value)
    },
    async delete(key: string) {
      return map.delete(key)
    },
  }

  return {
    ...txnOps,
    async transaction<T>(
      closure: (txn: DurableObjectTransactionLike) => Promise<T>,
    ): Promise<T> {
      const next = lock.then(async () => closure(txnOps))
      // Mask the next lock-handle's rejection so a failed transaction doesn't
      // poison every subsequent transaction on this storage instance.
      lock = next.then(
        () => undefined,
        () => undefined,
      )
      return next
    },
  }
}
