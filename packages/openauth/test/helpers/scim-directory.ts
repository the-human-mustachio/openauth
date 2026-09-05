/**
 * In-memory `ScimDirectory` — **tests only**.
 *
 * Deliberately not shipped as a `src/adapters/` implementation: real
 * SCIM persistence is the host's user model, and offering a bundled one
 * would invite hosts to store users in the library, which is exactly
 * what `SCIM-AD2` says not to do. This exists so the protocol layer can
 * be exercised end to end.
 *
 * It does implement the filter AST honestly, because that is the part a
 * host has to get right and the tests should prove is expressible.
 */
import type { ScimDirectory } from "../../src/ports/scim-directory"
import { err, ok, type Result } from "../../src/types/result"
import { authError } from "../../src/types/error"
import type {
  ScimFilter,
  ScimPage,
  ScimUserPatch,
  ScimUserQuery,
  ScimUserRecord,
  ScimUserWrite,
} from "../../src/types/scim"
import type { TenantId } from "../../src/types/tenant"

function matches(user: ScimUserRecord, filter: ScimFilter): boolean {
  if (filter.op === "and") {
    return matches(user, filter.left) && matches(user, filter.right)
  }
  switch (filter.attribute) {
    case "id":
      return user.id === filter.value
    case "userName":
      return user.userName === filter.value
    case "externalId":
      return user.externalId === filter.value
    case "active":
      return user.active === filter.value
    case "emails.value":
      return (user.emails ?? []).some((e) => e.value === filter.value)
  }
}

export class MemoryScimDirectory implements ScimDirectory {
  #users = new Map<string, ScimUserRecord>()
  #seq = 0
  #now: () => number

  constructor(now: () => number = () => Date.now()) {
    this.#now = now
  }

  #key(t: TenantId, id: string): string {
    return `${t}:${id}`
  }

  #all(t: TenantId): ScimUserRecord[] {
    const prefix = `${t}:`
    return [...this.#users.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .map(([, v]) => v)
  }

  /** Test affordance: seed a record without going through SCIM. */
  seed(t: TenantId, user: ScimUserRecord): ScimUserRecord {
    this.#users.set(this.#key(t, user.id), user)
    return user
  }

  async getUser(
    t: TenantId,
    id: string,
  ): Promise<Result<ScimUserRecord | null>> {
    return ok(this.#users.get(this.#key(t, id)) ?? null)
  }

  async findUsers(
    t: TenantId,
    query: ScimUserQuery,
  ): Promise<Result<ScimPage<ScimUserRecord>>> {
    const all = this.#all(t)
    const matched = query.filter
      ? all.filter((u) => matches(u, query.filter as ScimFilter))
      : all
    // startIndex is 1-based — the slice offset is one less.
    const start = Math.max(0, query.startIndex - 1)
    return ok({
      resources: matched.slice(start, start + query.count),
      totalResults: matched.length,
    })
  }

  async createUser(
    t: TenantId,
    user: ScimUserWrite,
  ): Promise<Result<ScimUserRecord>> {
    const clash = this.#all(t).some((u) => u.userName === user.userName)
    if (clash) {
      return err(
        authError.conflict(
          `userName "${user.userName}" already exists`,
          "userName",
        ),
      )
    }
    const now = this.#now()
    const record: ScimUserRecord = {
      id: `usr_${++this.#seq}`,
      ...user,
      createdAt: now,
      updatedAt: now,
    }
    this.#users.set(this.#key(t, record.id), record)
    return ok(record)
  }

  async replaceUser(
    t: TenantId,
    id: string,
    user: ScimUserWrite,
  ): Promise<Result<ScimUserRecord>> {
    const existing = this.#users.get(this.#key(t, id))
    if (!existing) return err(authError.invalidRequest("no such user"))
    const clash = this.#all(t).some(
      (u) => u.id !== id && u.userName === user.userName,
    )
    if (clash) {
      return err(
        authError.conflict(
          `userName "${user.userName}" already exists`,
          "userName",
        ),
      )
    }
    // PUT is a replace: attributes absent from the payload are cleared.
    const record: ScimUserRecord = {
      id,
      ...user,
      createdAt: existing.createdAt,
      updatedAt: this.#now(),
    }
    this.#users.set(this.#key(t, id), record)
    return ok(record)
  }

  async patchUser(
    t: TenantId,
    id: string,
    patch: ScimUserPatch,
  ): Promise<Result<ScimUserRecord>> {
    const existing = this.#users.get(this.#key(t, id))
    if (!existing) return err(authError.invalidRequest("no such user"))

    const next: ScimUserRecord = { ...existing, updatedAt: this.#now() }
    // Present ⇒ set. `null` ⇒ clear. Absent ⇒ untouched.
    for (const [k, v] of Object.entries(patch)) {
      if (v === null) delete (next as Record<string, unknown>)[k]
      else if (v !== undefined) (next as Record<string, unknown>)[k] = v
    }
    this.#users.set(this.#key(t, id), next)
    return ok(next)
  }

  async deleteUser(t: TenantId, id: string): Promise<Result<void>> {
    this.#users.delete(this.#key(t, id))
    return ok(undefined)
  }
}
