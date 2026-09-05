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
  ScimGroupMember,
  ScimGroupPatch,
  ScimGroupQuery,
  ScimGroupRecord,
  ScimGroupWrite,
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
    default:
      return false
  }
}

function groupMatches(group: ScimGroupRecord, filter: ScimFilter): boolean {
  if (filter.op === "and") {
    return groupMatches(group, filter.left) && groupMatches(group, filter.right)
  }
  switch (filter.attribute) {
    case "id":
      return group.id === filter.value
    case "displayName":
      return group.displayName === filter.value
    case "externalId":
      return group.externalId === filter.value
    default:
      return false
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

  // ─── Groups ───

  #groups = new Map<string, ScimGroupRecord>()
  #gseq = 0

  #allGroups(t: TenantId): ScimGroupRecord[] {
    const prefix = `${t}:`
    return [...this.#groups.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .map(([, v]) => v)
  }

  seedGroup(t: TenantId, group: ScimGroupRecord): ScimGroupRecord {
    this.#groups.set(this.#key(t, group.id), group)
    return group
  }

  async getGroup(
    t: TenantId,
    id: string,
  ): Promise<Result<ScimGroupRecord | null>> {
    return ok(this.#groups.get(this.#key(t, id)) ?? null)
  }

  async findGroups(
    t: TenantId,
    query: ScimGroupQuery,
  ): Promise<Result<ScimPage<ScimGroupRecord>>> {
    const all = this.#allGroups(t)
    const matched = query.filter
      ? all.filter((g) => groupMatches(g, query.filter as ScimFilter))
      : all
    const start = Math.max(0, query.startIndex - 1)
    const page = matched.slice(start, start + query.count)
    return ok({
      // Honour excludeMembers, as a real host should: drop the member
      // list rather than loading it.
      resources: query.excludeMembers
        ? page.map(({ members: _drop, ...rest }) => rest)
        : page,
      totalResults: matched.length,
    })
  }

  async createGroup(
    t: TenantId,
    group: ScimGroupWrite,
  ): Promise<Result<ScimGroupRecord>> {
    if (this.#allGroups(t).some((g) => g.displayName === group.displayName)) {
      return err(
        authError.conflict(
          `displayName "${group.displayName}" already exists`,
          "displayName",
        ),
      )
    }
    const now = this.#now()
    const record: ScimGroupRecord = {
      id: `grp_${++this.#gseq}`,
      members: [],
      ...group,
      createdAt: now,
      updatedAt: now,
    }
    this.#groups.set(this.#key(t, record.id), record)
    return ok(record)
  }

  async replaceGroup(
    t: TenantId,
    id: string,
    group: ScimGroupWrite,
  ): Promise<Result<ScimGroupRecord>> {
    const existing = this.#groups.get(this.#key(t, id))
    if (!existing) return err(authError.invalidRequest("no such group"))
    const record: ScimGroupRecord = {
      id,
      members: [],
      ...group,
      createdAt: existing.createdAt,
      updatedAt: this.#now(),
    }
    this.#groups.set(this.#key(t, id), record)
    return ok(record)
  }

  async patchGroup(
    t: TenantId,
    id: string,
    patch: ScimGroupPatch,
  ): Promise<Result<ScimGroupRecord>> {
    const existing = this.#groups.get(this.#key(t, id))
    if (!existing) return err(authError.invalidRequest("no such group"))

    let members: ScimGroupMember[] = [...(existing.members ?? [])]
    if (patch.members !== undefined) {
      members = [...patch.members]
    } else {
      // Incremental, and idempotent both ways — IdPs retry.
      for (const m of patch.addMembers ?? []) {
        if (!members.some((e) => e.value === m.value)) members.push(m)
      }
      if (patch.removeMembers) {
        const drop = new Set(patch.removeMembers)
        members = members.filter((e) => !drop.has(e.value))
      }
    }

    const next: ScimGroupRecord = {
      ...existing,
      ...(patch.displayName !== undefined
        ? { displayName: patch.displayName }
        : {}),
      members,
      updatedAt: this.#now(),
    }
    if (patch.externalId === null) delete next.externalId
    else if (patch.externalId !== undefined) next.externalId = patch.externalId

    this.#groups.set(this.#key(t, id), next)
    return ok(next)
  }

  async deleteGroup(t: TenantId, id: string): Promise<Result<void>> {
    this.#groups.delete(this.#key(t, id))
    return ok(undefined)
  }
}
