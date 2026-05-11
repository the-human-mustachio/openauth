/**
 * In-process `KVNamespace` shim. Map-backed; eventual-consistency simulation
 * is deliberately omitted so the conformance suite (which checks `get` after
 * `put` immediately) passes — eventual-consistency behavior under realistic
 * lag is verified in operational tests outside this package.
 */
import type { KVNamespaceLike } from "../../src/adapters/kv/types"

export function createKvShim(): KVNamespaceLike {
  const map = new Map<string, string>()
  return {
    async get(key: string, _type?: "json") {
      const v = map.get(key)
      if (v === undefined) return null
      if (_type === "json") return JSON.parse(v) as never
      return v as never
    },
    async put(key: string, value: string) {
      map.set(key, value)
    },
    async delete(key: string) {
      map.delete(key)
    },
    async list(options: { prefix?: string; cursor?: string | null; limit?: number } = {}) {
      const all = [...map.keys()].sort()
      const prefix = options.prefix ?? ""
      const filtered = all.filter((k) => k.startsWith(prefix))
      return {
        keys: filtered.map((name) => ({ name })),
        list_complete: true,
      }
    },
  }
}
