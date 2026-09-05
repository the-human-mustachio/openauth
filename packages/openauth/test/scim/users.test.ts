/**
 * SCIM Phase 1 conformance — cases 1–14 of the matrix in
 * `docs/plans/claude/scim-plan.md`.
 *
 * Driven through `handleScimRequest`, which is the whole protocol
 * surface (the HTTP handler only parses in and serializes out). The
 * envelope details asserted here — string `status`, capital-R
 * `Resources`, 1-based `startIndex` — are the ones Okta's validator
 * checks and that are easy to get quietly wrong.
 */
import { describe, expect, test } from "bun:test"

import { handleScimRequest } from "../../src/domain/scim/handle"
import { hashClientSecret } from "../../src/domain/token"
import type { TenantConfig } from "../../src/types/tenant"
import { asTenantId } from "../../src/types/tenant"

import { MemoryScimDirectory } from "../helpers/scim-directory"
import { buildTenant, tenantContextFor } from "../helpers/tenant"

const TOKEN = "scim-token-abc123"
const BASE = "https://idp.example/scim/v2"
const TENANT = asTenantId("acme")

async function scimTenant(
  over: Partial<TenantConfig["scim"]> = {},
): Promise<TenantConfig> {
  const base = await buildTenant()
  return {
    ...base,
    scim: {
      enabled: true,
      tokenHash: await hashClientSecret(TOKEN),
      ...over,
    },
  }
}

type CallOpts = {
  method?: string
  path?: string
  query?: string
  body?: unknown
  token?: string | null
  tenant?: TenantConfig
  directory?: MemoryScimDirectory
}

async function call(opts: CallOpts = {}) {
  const tenant = opts.tenant ?? (await scimTenant())
  const directory =
    opts.directory ?? new MemoryScimDirectory(() => 1_700_000_000_000)
  const token = opts.token === undefined ? TOKEN : opts.token
  const res = await handleScimRequest({
    tenant: tenantContextFor(tenant),
    method: opts.method ?? "GET",
    path: opts.path ?? "/Users",
    query: new URLSearchParams(opts.query ?? ""),
    body: opts.body ?? null,
    authorization: token === null ? null : `Bearer ${token}`,
    baseUrl: BASE,
    directory,
  })
  return { res, directory, tenant }
}

const VALID_USER = {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  userName: "alice@corp.example",
  name: { givenName: "Alice", familyName: "Adams" },
  emails: [{ value: "alice@corp.example", type: "work", primary: true }],
  externalId: "00u1abc",
}

describe("SCIM — authentication (cases 1, 2)", () => {
  test("valid bearer token is accepted", async () => {
    const { res } = await call({ path: "/ServiceProviderConfig" })
    expect(res.status).toBe(200)
  })

  test("wrong token → 401", async () => {
    const { res } = await call({ token: "not-the-token" })
    expect(res.status).toBe(401)
    expect(res.body?.["schemas"]).toEqual([
      "urn:ietf:params:scim:api:messages:2.0:Error",
    ])
    // `status` is a STRING in the SCIM error envelope.
    expect(res.body?.["status"]).toBe("401")
  })

  test("missing Authorization header → 401", async () => {
    const { res } = await call({ token: null })
    expect(res.status).toBe(401)
  })

  test("SCIM disabled for the tenant → 403, never 404", async () => {
    const tenant = await scimTenant({ enabled: false })
    const { res } = await call({ tenant })
    // 403 rather than 404: a 404 would let an unauthenticated caller
    // probe which tenants exist.
    expect(res.status).toBe(403)
  })

  test("no scim config at all → 403", async () => {
    const tenant = await buildTenant()
    const { res } = await call({ tenant })
    expect(res.status).toBe(403)
  })

  test("auth is checked before routing (no endpoint probing)", async () => {
    const { res } = await call({ path: "/NotARealThing", token: "wrong" })
    expect(res.status).toBe(401)
  })
})

describe("SCIM — create (cases 3, 4, 13)", () => {
  test("POST /Users → 201 with id, meta and location", async () => {
    const { res } = await call({
      method: "POST",
      path: "/Users",
      body: VALID_USER,
    })
    expect(res.status).toBe(201)
    expect(res.body?.["id"]).toBeTruthy()
    expect(res.body?.["userName"]).toBe("alice@corp.example")
    expect(res.body?.["active"]).toBe(true) // SCIM default resolved here
    const meta = res.body?.["meta"] as Record<string, unknown>
    expect(meta["resourceType"]).toBe("User")
    expect(meta["location"]).toBe(`${BASE}/Users/${res.body?.["id"]}`)
    expect(meta["created"]).toBe("2023-11-14T22:13:20.000Z")
  })

  test("duplicate userName → 409 uniqueness", async () => {
    const directory = new MemoryScimDirectory()
    await call({ method: "POST", path: "/Users", body: VALID_USER, directory })
    const { res } = await call({
      method: "POST",
      path: "/Users",
      body: VALID_USER,
      directory,
    })
    expect(res.status).toBe(409)
    expect(res.body?.["scimType"]).toBe("uniqueness")
  })

  test("missing userName → 400 invalidValue", async () => {
    const { res } = await call({
      method: "POST",
      path: "/Users",
      body: { schemas: [], emails: [] },
    })
    expect(res.status).toBe(400)
    expect(res.body?.["scimType"]).toBe("invalidValue")
  })

  test("password in the payload is refused, not silently dropped", async () => {
    const { res } = await call({
      method: "POST",
      path: "/Users",
      body: { ...VALID_USER, password: "hunter2" },
    })
    expect(res.status).toBe(400)
    expect(String(res.body?.["detail"])).toContain("password")
  })

  test("enterprise extension round-trips", async () => {
    const { res } = await call({
      method: "POST",
      path: "/Users",
      body: {
        ...VALID_USER,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
          department: "Platform",
          manager: { value: "usr_9" },
        },
      },
    })
    expect(res.status).toBe(201)
    const ent = res.body?.[
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ] as Record<string, unknown>
    expect(ent["department"]).toBe("Platform")
    expect(res.body?.["schemas"]).toContain(
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    )
  })
})

describe("SCIM — list, filter, pagination (cases 5, 6, 7)", () => {
  async function seeded() {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seed(TENANT, {
      id: "u1",
      userName: "alice@corp.example",
      externalId: "ext-alice",
      active: true,
      emails: [{ value: "alice@corp.example", type: "work" }],
    })
    directory.seed(TENANT, {
      id: "u2",
      userName: "bob@corp.example",
      externalId: "ext-bob",
      active: false,
    })
    directory.seed(TENANT, {
      id: "u3",
      userName: "carol@corp.example",
      active: true,
    })
    return directory
  }

  test("unfiltered list returns a well-formed ListResponse", async () => {
    const { res } = await call({ directory: await seeded() })
    expect(res.status).toBe(200)
    expect(res.body?.["schemas"]).toEqual([
      "urn:ietf:params:scim:api:messages:2.0:ListResponse",
    ])
    expect(res.body?.["totalResults"]).toBe(3)
    expect(res.body?.["startIndex"]).toBe(1)
    // Capital R — the spec's casing.
    expect((res.body?.["Resources"] as unknown[]).length).toBe(3)
  })

  test('filter userName eq "…" — the Okta existence check', async () => {
    const { res } = await call({
      directory: await seeded(),
      query: 'filter=userName eq "alice@corp.example"',
    })
    expect(res.body?.["totalResults"]).toBe(1)
    const first = (res.body?.["Resources"] as Record<string, unknown>[])[0]
    expect(first?.["userName"]).toBe("alice@corp.example")
  })

  test("filter on externalId, active, id, and Entra's complex email path", async () => {
    const directory = await seeded()
    const byExternal = await call({
      directory,
      query: 'filter=externalId eq "ext-bob"',
    })
    expect(byExternal.res.body?.["totalResults"]).toBe(1)

    const byActive = await call({ directory, query: "filter=active eq false" })
    expect(byActive.res.body?.["totalResults"]).toBe(1)

    const byId = await call({ directory, query: 'filter=id eq "u3"' })
    expect(byId.res.body?.["totalResults"]).toBe(1)

    const byEmail = await call({
      directory,
      query: 'filter=emails[type eq "work"].value eq "alice@corp.example"',
    })
    expect(byEmail.res.body?.["totalResults"]).toBe(1)
  })

  test('two terms joined by "and"', async () => {
    const { res } = await call({
      directory: await seeded(),
      query: 'filter=userName eq "alice@corp.example" and active eq true',
    })
    expect(res.body?.["totalResults"]).toBe(1)
  })

  test("unsupported filter → 400 invalidFilter naming what works", async () => {
    const cases = [
      'filter=userName co "alice"',
      "filter=title pr",
      'filter=(userName eq "a") or (userName eq "b")',
      'filter=nickName eq "ally"',
    ]
    for (const query of cases) {
      const { res } = await call({ directory: await seeded(), query })
      expect(res.status).toBe(400)
      expect(res.body?.["scimType"]).toBe("invalidFilter")
      // The refusal must tell the operator what IS supported, or the
      // gap is invisible.
      expect(String(res.body?.["detail"])).toContain("userName eq")
    }
  })

  test("pagination is 1-based and itemsPerPage is honest", async () => {
    const directory = await seeded()
    const first = await call({ directory, query: "startIndex=1&count=2" })
    expect(first.res.body?.["startIndex"]).toBe(1)
    expect(first.res.body?.["itemsPerPage"]).toBe(2)
    expect(first.res.body?.["totalResults"]).toBe(3)

    const second = await call({ directory, query: "startIndex=3&count=2" })
    expect(second.res.body?.["itemsPerPage"]).toBe(1)
    // totalResults is the full match count, not the page size — Okta
    // drives its paging loop off this.
    expect(second.res.body?.["totalResults"]).toBe(3)
    const ids = (
      second.res.body?.["Resources"] as Record<string, unknown>[]
    ).map((u) => u["id"])
    expect(ids).toEqual(["u3"])
  })

  test("startIndex below 1 is treated as 1, not as an offset", async () => {
    const { res } = await call({
      directory: await seeded(),
      query: "startIndex=0",
    })
    expect(res.body?.["startIndex"]).toBe(1)
    expect((res.body?.["Resources"] as unknown[]).length).toBe(3)
  })

  test("count is clamped to the connection maximum", async () => {
    const tenant = await scimTenant({ maxPageSize: 2 })
    const { res } = await call({
      tenant,
      directory: await seeded(),
      query: "count=1000",
    })
    expect(res.body?.["itemsPerPage"]).toBe(2)
  })
})

describe("SCIM — read, replace, delete (cases 11, 12)", () => {
  test("GET /Users/:id → 200; unknown id → 404", async () => {
    const directory = new MemoryScimDirectory()
    directory.seed(TENANT, { id: "u1", userName: "a@b.c", active: true })

    const found = await call({ directory, path: "/Users/u1" })
    expect(found.res.status).toBe(200)
    expect(found.res.body?.["userName"]).toBe("a@b.c")

    const missing = await call({ directory, path: "/Users/nope" })
    expect(missing.res.status).toBe(404)
  })

  test("PUT replaces rather than merges", async () => {
    const directory = new MemoryScimDirectory()
    directory.seed(TENANT, {
      id: "u1",
      userName: "a@b.c",
      active: true,
      displayName: "Original",
      emails: [{ value: "a@b.c", type: "work" }],
    })
    const { res } = await call({
      directory,
      method: "PUT",
      path: "/Users/u1",
      body: { userName: "a@b.c", active: true },
    })
    expect(res.status).toBe(200)
    // Absent attributes are cleared by a replace, per RFC 7644 §3.5.1.
    expect(res.body?.["displayName"]).toBeUndefined()
    expect(res.body?.["emails"]).toBeUndefined()
  })

  test("DELETE reaches deleteUser and does NOT deactivate", async () => {
    const directory = new MemoryScimDirectory()
    directory.seed(TENANT, { id: "u1", userName: "a@b.c", active: true })

    const del = await call({ directory, method: "DELETE", path: "/Users/u1" })
    expect(del.res.status).toBe(204)
    expect(del.res.body).toBeNull()

    // SCIM-AD8: a delete is a delete. If it had been quietly remapped to
    // deactivation the record would still be here, inactive.
    const after = await directory.getUser(TENANT, "u1")
    expect(after.ok && after.value).toBeNull()
  })

  test("DELETE on an unknown id → 404", async () => {
    const { res } = await call({ method: "DELETE", path: "/Users/nope" })
    expect(res.status).toBe(404)
  })

  test("unsupported method on a collection → 405", async () => {
    const { res } = await call({ method: "PUT", path: "/Users" })
    expect(res.status).toBe(405)
  })
})

describe("SCIM — discovery (case 14)", () => {
  test("ServiceProviderConfig advertises only what we serve", async () => {
    const { res } = await call({ path: "/ServiceProviderConfig" })
    expect(res.status).toBe(200)
    expect((res.body?.["patch"] as Record<string, unknown>)["supported"]).toBe(
      true,
    )
    expect((res.body?.["filter"] as Record<string, unknown>)["supported"]).toBe(
      true,
    )
    // Declared false because they are genuinely not implemented —
    // advertising a capability we lack is worse than never claiming it.
    for (const cap of ["bulk", "changePassword", "sort", "etag"]) {
      expect((res.body?.[cap] as Record<string, unknown>)["supported"]).toBe(
        false,
      )
    }
  })

  test("ResourceTypes and Schemas are well-formed lists", async () => {
    const rt = await call({ path: "/ResourceTypes" })
    expect(rt.res.status).toBe(200)
    const types = (rt.res.body?.["Resources"] as Record<string, unknown>[]).map(
      (r) => r["id"],
    )
    expect(types).toContain("User")

    const sc = await call({ path: "/Schemas" })
    expect(sc.res.status).toBe(200)
    const ids = (sc.res.body?.["Resources"] as Record<string, unknown>[]).map(
      (s) => s["id"],
    )
    expect(ids).toContain("urn:ietf:params:scim:schemas:core:2.0:User")
  })

  test("discovery advertises Group only when the host implements it", async () => {
    // Advertising a resource type we answer 501 for would send a client
    // straight into a failure it was told to expect to work.
    const withGroups = await call({ path: "/ResourceTypes" })
    expect(
      (withGroups.res.body?.["Resources"] as Record<string, unknown>[]).map(
        (r) => r["id"],
      ),
    ).toEqual(["User", "Group"])

    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    const usersOnly = {
      getUser: directory.getUser.bind(directory),
      findUsers: directory.findUsers.bind(directory),
      createUser: directory.createUser.bind(directory),
      replaceUser: directory.replaceUser.bind(directory),
      patchUser: directory.patchUser.bind(directory),
      deleteUser: directory.deleteUser.bind(directory),
    }
    const without = await call({
      path: "/ResourceTypes",
      directory: usersOnly as unknown as MemoryScimDirectory,
    })
    expect(
      (without.res.body?.["Resources"] as Record<string, unknown>[]).map(
        (r) => r["id"],
      ),
    ).toEqual(["User"])

    const schemasWithout = await call({
      path: "/Schemas",
      directory: usersOnly as unknown as MemoryScimDirectory,
    })
    expect(
      (schemasWithout.res.body?.["Resources"] as Record<string, unknown>[]).map(
        (s) => s["id"],
      ),
    ).not.toContain("urn:ietf:params:scim:schemas:core:2.0:Group")
  })

  test("discovery endpoints reject non-GET", async () => {
    const { res } = await call({
      method: "POST",
      path: "/ServiceProviderConfig",
    })
    expect(res.status).toBe(405)
  })
})

describe("SCIM — not-yet-implemented surfaces", () => {
  test("/Groups answers 501 when the host implements no group methods", async () => {
    // Groups are optional on the port. A host that only needs user
    // provisioning gets an honest 501 rather than a runtime failure
    // partway through an IdP's group push.
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    const usersOnly = {
      getUser: directory.getUser.bind(directory),
      findUsers: directory.findUsers.bind(directory),
      createUser: directory.createUser.bind(directory),
      replaceUser: directory.replaceUser.bind(directory),
      patchUser: directory.patchUser.bind(directory),
      deleteUser: directory.deleteUser.bind(directory),
    }
    const { res } = await call({
      path: "/Groups",
      directory: usersOnly as unknown as MemoryScimDirectory,
    })
    expect(res.status).toBe(501)
  })

  test("an unknown endpoint is a 404", async () => {
    const { res } = await call({ path: "/Nonsense" })
    expect(res.status).toBe(404)
  })
})

describe("review regressions", () => {
  test("finding 4 — parentheses inside a quoted value are not a grouped expression", async () => {
    // "Sales (EMEA)" is an ordinary group name. Rejecting it made Okta's
    // existence lookup fail, and Okta answers a failed lookup by
    // creating a duplicate.
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seed(TENANT, {
      id: "u1",
      userName: "Sales (EMEA)",
      active: true,
    })
    const { res } = await call({
      directory,
      query: 'filter=userName eq "Sales (EMEA)"',
    })
    expect(res.status).toBe(200)
    expect(res.body?.["totalResults"]).toBe(1)
  })

  test('finding 4 — the words "or" / "not" inside a value are just text', async () => {
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seed(TENANT, { id: "u1", userName: "jack or jill", active: true })
    directory.seed(TENANT, { id: "u2", userName: "not really", active: true })

    const or = await call({
      directory,
      query: 'filter=userName eq "jack or jill"',
    })
    expect(or.res.status).toBe(200)
    expect(or.res.body?.["totalResults"]).toBe(1)

    const not = await call({
      directory,
      query: 'filter=userName eq "not really"',
    })
    expect(not.res.status).toBe(200)
    expect(not.res.body?.["totalResults"]).toBe(1)
  })

  test("finding 4 — real grouping and real or/not are still refused", async () => {
    for (const query of [
      'filter=(userName eq "a") and (active eq true)',
      'filter=userName eq "a" or userName eq "b"',
      'filter=not (userName eq "a")',
    ]) {
      const { res } = await call({ query })
      expect(res.status).toBe(400)
      expect(res.body?.["scimType"]).toBe("invalidFilter")
    }
  })

  test("finding 6 — a negative count means zero, not a full page", async () => {
    // RFC 7644 §3.4.2.4: "A negative value SHALL be interpreted as 0."
    const directory = new MemoryScimDirectory(() => 1_700_000_000_000)
    directory.seed(TENANT, { id: "u1", userName: "a@b.c", active: true })
    const { res } = await call({ directory, query: "count=-1" })
    expect(res.body?.["itemsPerPage"]).toBe(0)
    expect((res.body?.["Resources"] as unknown[]).length).toBe(0)
    // The match count is still reported honestly.
    expect(res.body?.["totalResults"]).toBe(1)
  })

  test("finding 7 — a create carries a Location header", async () => {
    const { res } = await call({
      method: "POST",
      path: "/Users",
      body: VALID_USER,
    })
    expect(res.status).toBe(201)
    // RFC 7644 §3.1, and Okta's validator checks for it.
    expect(res.headers?.["location"]).toBe(`${BASE}/Users/${res.body?.["id"]}`)
    // It must agree with meta.location rather than being rebuilt.
    expect(res.headers?.["location"]).toBe(
      (res.body?.["meta"] as Record<string, string>)["location"],
    )
  })
})
