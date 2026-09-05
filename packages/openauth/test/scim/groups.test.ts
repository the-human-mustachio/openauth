/**
 * SCIM Groups — conformance case 15.
 *
 * Group push is where membership deltas live, and where Okta and Entra
 * diverge most. These tests pin the shapes each actually sends and the
 * one thing that matters for scale: an incremental add stays incremental
 * (`SCIM-AD9`), so a host with a large group is never asked to rewrite
 * its whole membership to add one person.
 */
import { describe, expect, test } from "bun:test"

import { handleScimRequest } from "../../src/domain/scim/handle"
import { normalizeGroupPatch } from "../../src/domain/scim/patch"
import { hashClientSecret } from "../../src/domain/token"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"

import { MemoryScimDirectory } from "../helpers/scim-directory"
import { buildTenant, tenantContextFor } from "../helpers/tenant"

const TOKEN = "scim-token-abc123"
const BASE = "https://idp.example/scim/v2"
const TENANT = asTenantId("acme")

async function scimTenant(): Promise<TenantConfig> {
  const base = await buildTenant()
  return {
    ...base,
    scim: { enabled: true, tokenHash: await hashClientSecret(TOKEN) },
  }
}

type CallOpts = {
  method?: string
  path?: string
  query?: string
  body?: unknown
  directory?: MemoryScimDirectory
  tenant?: TenantConfig
}

async function call(opts: CallOpts = {}) {
  const tenant = opts.tenant ?? (await scimTenant())
  const directory =
    opts.directory ?? new MemoryScimDirectory(() => 1_700_000_000_000)
  const res = await handleScimRequest({
    tenant: tenantContextFor(tenant),
    method: opts.method ?? "GET",
    path: opts.path ?? "/Groups",
    query: new URLSearchParams(opts.query ?? ""),
    body: opts.body ?? null,
    authorization: `Bearer ${TOKEN}`,
    baseUrl: BASE,
    directory,
  })
  return { res, directory }
}

const patchOp = (ops: unknown[]) => ({
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: ops,
})

describe("SCIM Groups — CRUD", () => {
  test("POST /Groups → 201 with id, meta and members", async () => {
    const { res } = await call({
      method: "POST",
      body: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: "Engineering",
        externalId: "grp-ext-1",
        members: [{ value: "u1", display: "Alice" }],
      },
    })
    expect(res.status).toBe(201)
    expect(res.body?.["displayName"]).toBe("Engineering")
    const members = res.body?.["members"] as Record<string, unknown>[]
    expect(members[0]?.["value"]).toBe("u1")
    // $ref and type are what a client follows back to the user.
    expect(members[0]?.["$ref"]).toBe(`${BASE}/Users/u1`)
    expect(members[0]?.["type"]).toBe("User")
    expect((res.body?.["meta"] as Record<string, string>)["resourceType"]).toBe(
      "Group",
    )
  })

  test("displayName is required", async () => {
    const { res } = await call({ method: "POST", body: { externalId: "x" } })
    expect(res.status).toBe(400)
    expect(res.body?.["scimType"]).toBe("invalidValue")
  })

  test("a duplicate displayName is a 409 uniqueness", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    await call({ method: "POST", body: { displayName: "Eng" }, directory })
    const { res } = await call({
      method: "POST",
      body: { displayName: "Eng" },
      directory,
    })
    expect(res.status).toBe(409)
    expect(res.body?.["scimType"]).toBe("uniqueness")
  })

  test("GET /Groups/:id, and 404 for an unknown id", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, {
      id: "g1",
      displayName: "Eng",
      members: [{ value: "u1" }],
    })
    const found = await call({ directory, path: "/Groups/g1" })
    expect(found.res.status).toBe(200)
    expect(found.res.body?.["displayName"]).toBe("Eng")

    const missing = await call({ directory, path: "/Groups/nope" })
    expect(missing.res.status).toBe(404)
  })

  test("filter by displayName", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, { id: "g1", displayName: "Eng", members: [] })
    directory.seedGroup(TENANT, { id: "g2", displayName: "Sales", members: [] })

    const { res } = await call({
      directory,
      query: 'filter=displayName eq "Sales"',
    })
    expect(res.body?.["totalResults"]).toBe(1)
  })

  test("filtering a Group by userName is a 400, not an empty list", async () => {
    // An empty list would read as "no such group" — a wrong answer
    // dressed up as a valid one.
    const { res } = await call({ query: 'filter=userName eq "alice"' })
    expect(res.status).toBe(400)
    expect(res.body?.["scimType"]).toBe("invalidFilter")
  })

  test("excludedAttributes=members omits membership entirely", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, {
      id: "g1",
      displayName: "Eng",
      members: [{ value: "u1" }],
    })
    const { res } = await call({
      directory,
      query: "excludedAttributes=members",
    })
    const first = (res.body?.["Resources"] as Record<string, unknown>[])[0]
    // Absent, not `[]` — an empty array would claim the group was emptied.
    expect(first).not.toHaveProperty("members")

    const withMembers = await call({ directory })
    const w = (withMembers.res.body?.["Resources"] as Record<
      string,
      unknown
    >[])[0]
    expect(w?.["members"]).toBeDefined()
  })

  test("DELETE /Groups/:id → 204", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, { id: "g1", displayName: "Eng", members: [] })
    const { res } = await call({
      directory,
      method: "DELETE",
      path: "/Groups/g1",
    })
    expect(res.status).toBe(204)
    const after = await directory.getGroup(TENANT, "g1")
    expect(after.ok && after.value).toBeNull()
  })
})

describe("membership deltas stay deltas (SCIM-AD9)", () => {
  test("Okta's add → addMembers, not a rewritten list", async () => {
    const r = normalizeGroupPatch(
      patchOp([
        { op: "add", path: "members", value: [{ value: "u2", display: "Bo" }] },
      ]),
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.addMembers).toEqual([{ value: "u2", display: "Bo" }])
    // The host must NOT be handed a full membership list to rewrite.
    expect(r.value.members).toBeUndefined()
    expect(r.value.removeMembers).toBeUndefined()
  })

  test('Okta\'s remove via members[value eq "…"] → removeMembers', async () => {
    const r = normalizeGroupPatch(
      patchOp([{ op: "remove", path: 'members[value eq "u2"]' }]),
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.removeMembers).toEqual(["u2"])
    expect(r.value.members).toBeUndefined()
  })

  test("Entra's remove with a value array → the same removeMembers", async () => {
    const r = normalizeGroupPatch(
      patchOp([
        { op: "remove", path: "members", value: [{ value: "u2" }] },
      ]),
    )
    expect(r.ok && r.value.removeMembers).toEqual(["u2"])
  })

  test("replace → a full members list, and no incremental fields", async () => {
    const r = normalizeGroupPatch(
      patchOp([
        { op: "replace", path: "members", value: [{ value: "u9" }] },
      ]),
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.members).toEqual([{ value: "u9" }])
    expect(r.value.addMembers).toBeUndefined()
    expect(r.value.removeMembers).toBeUndefined()
  })

  test("a replace followed by an add folds into the replacement", async () => {
    // The host must never receive `members` alongside `addMembers` —
    // it would have to invent an ordering rule to interpret them.
    const r = normalizeGroupPatch(
      patchOp([
        { op: "replace", path: "members", value: [{ value: "u1" }] },
        { op: "add", path: "members", value: [{ value: "u2" }] },
      ]),
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.members).toEqual([{ value: "u1" }, { value: "u2" }])
    expect(r.value.addMembers).toBeUndefined()
  })

  test("removing all members is a replace with an empty list", async () => {
    const r = normalizeGroupPatch(patchOp([{ op: "remove", path: "members" }]))
    expect(r.ok && r.value.members).toEqual([])
  })

  test("adding the same member twice is deduplicated", async () => {
    const r = normalizeGroupPatch(
      patchOp([
        { op: "add", path: "members", value: [{ value: "u1" }] },
        { op: "add", path: "members", value: [{ value: "u1" }] },
      ]),
    )
    expect(r.ok && r.value.addMembers).toEqual([{ value: "u1" }])
  })

  test("displayName rename, both spellings", async () => {
    const withPath = normalizeGroupPatch(
      patchOp([{ op: "replace", path: "displayName", value: "Platform" }]),
    )
    expect(withPath.ok && withPath.value.displayName).toBe("Platform")

    const pathless = normalizeGroupPatch(
      patchOp([{ op: "replace", value: { displayName: "Platform" } }]),
    )
    expect(pathless.ok && pathless.value.displayName).toBe("Platform")
  })

  test("an unsupported group path is rejected, not dropped", async () => {
    const r = normalizeGroupPatch(
      patchOp([{ op: "replace", path: "members[type eq \"x\"]", value: [] }]),
    )
    expect(r.ok).toBe(false)
  })
})

describe("membership PATCH end to end", () => {
  test("add, then remove, through the real dispatcher", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, {
      id: "g1",
      displayName: "Eng",
      members: [{ value: "u1" }],
    })

    const added = await call({
      directory,
      method: "PATCH",
      path: "/Groups/g1",
      body: patchOp([
        { op: "add", path: "members", value: [{ value: "u2" }] },
      ]),
    })
    expect(added.res.status).toBe(200)
    expect(
      (added.res.body?.["members"] as Record<string, unknown>[]).map(
        (m) => m["value"],
      ),
    ).toEqual(["u1", "u2"])

    const removed = await call({
      directory,
      method: "PATCH",
      path: "/Groups/g1",
      body: patchOp([{ op: "remove", path: 'members[value eq "u1"]' }]),
    })
    expect(
      (removed.res.body?.["members"] as Record<string, unknown>[]).map(
        (m) => m["value"],
      ),
    ).toEqual(["u2"])
  })

  test("removing a member who is not in the group succeeds quietly", async () => {
    // IdPs retry; a 4xx here would stall a group push forever.
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, { id: "g1", displayName: "Eng", members: [] })
    const { res } = await call({
      directory,
      method: "PATCH",
      path: "/Groups/g1",
      body: patchOp([{ op: "remove", path: 'members[value eq "ghost"]' }]),
    })
    expect(res.status).toBe(200)
  })

  test("PATCH on an unknown group is a 404", async () => {
    const { res } = await call({
      method: "PATCH",
      path: "/Groups/nope",
      body: patchOp([{ op: "add", path: "members", value: [{ value: "u" }] }]),
    })
    expect(res.status).toBe(404)
  })

  test("PUT replaces membership wholesale", async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seedGroup(TENANT, {
      id: "g1",
      displayName: "Eng",
      members: [{ value: "u1" }, { value: "u2" }],
    })
    const { res } = await call({
      directory,
      method: "PUT",
      path: "/Groups/g1",
      body: { displayName: "Eng", members: [{ value: "u3" }] },
    })
    expect(res.status).toBe(200)
    expect(
      (res.body?.["members"] as Record<string, unknown>[]).map(
        (m) => m["value"],
      ),
    ).toEqual(["u3"])
  })
})
