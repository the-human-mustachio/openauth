/**
 * SCIM over the real router — the parts the domain tests cannot cover.
 *
 * `handleScimRequest` is exercised directly elsewhere; what only shows
 * up here is the HTTP edge: mount-path slicing, JSON body handling,
 * `application/scim+json` on the way out, a bodiless 204, and the 501
 * a deployment gets when it never supplied a `scimDirectory`.
 */
import { describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { hashClientSecret } from "../../src/domain/token"
import { ok } from "../../src/types/result"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"

import { MemoryScimDirectory } from "../helpers/scim-directory"
import { buildStateKeys } from "../helpers/state-keys"
import { buildTenant } from "../helpers/tenant"

const TOKEN = "scim-token-abc123"
const ISSUER = "https://idp.example"
const TENANT = asTenantId("acme")

async function harness(opts: { withDirectory?: boolean } = {}) {
  const base = await buildTenant()
  const tenant: TenantConfig = {
    ...base,
    scim: { enabled: true, tokenHash: await hashClientSecret(TOKEN) },
  }
  const clock = () => 1_700_000_000_000
  const keyStore = new MemoryKeyStore({ clock })
  const directory = new MemoryScimDirectory(clock)

  const idp = createIdP({
    resolveTenant: async () => ok(TENANT),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({ keyStore, clock }),
    sessionStore: new MemorySessionStore({ clock }),
    keyStore,
    auditLog: new MemoryAuditLog(),
    issuerUrl: ISSUER,
    methods: {},
    subjects: {} as never,
    success: async () => ({ type: "user", properties: {} }) as never,
    ...(opts.withDirectory === false ? {} : { scimDirectory: directory }),
  })

  const call = (
    path: string,
    init: RequestInit & { token?: string | null } = {},
  ) => {
    const { token, ...rest } = init
    const headers = new Headers(rest.headers)
    const bearer = token === undefined ? TOKEN : token
    if (bearer !== null) headers.set("authorization", `Bearer ${bearer}`)
    return idp.handle(
      new Request(`${ISSUER}/scim/v2${path}`, { ...rest, headers }),
    )
  }

  return { call, directory }
}

describe("SCIM over HTTP", () => {
  test("the mount prefix is stripped so routing sees /Users", async () => {
    const { call, directory } = await harness()
    directory.seed(TENANT, { id: "u1", userName: "a@b.c", active: true })

    const res = await call("/Users")
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body["totalResults"]).toBe(1)
  })

  test("responses carry application/scim+json and are never cached", async () => {
    const { call } = await harness()
    const res = await call("/ServiceProviderConfig")
    expect(res.headers.get("content-type")).toContain("application/scim+json")
    expect(res.headers.get("cache-control")).toBe("no-store")
  })

  test("a JSON body round-trips into a create", async () => {
    const { call } = await harness()
    const res = await call("/Users", {
      method: "POST",
      headers: { "content-type": "application/scim+json" },
      body: JSON.stringify({ userName: "alice@corp.example" }),
    })
    expect(res.status).toBe(201)
    const body = (await res.json()) as Record<string, unknown>
    expect(body["userName"]).toBe("alice@corp.example")
    expect((body["meta"] as Record<string, string>)["location"]).toBe(
      `${ISSUER}/scim/v2/Users/${body["id"]}`,
    )
  })

  test("a malformed JSON body is a SCIM 400, not a thrown 500", async () => {
    const { call } = await harness()
    const res = await call("/Users", {
      method: "POST",
      headers: { "content-type": "application/scim+json" },
      body: "{not json",
    })
    expect(res.status).toBe(400)
    const body = (await res.json()) as Record<string, unknown>
    expect(body["scimType"]).toBe("invalidSyntax")
  })

  test("DELETE returns a bodiless 204", async () => {
    const { call, directory } = await harness()
    directory.seed(TENANT, { id: "u1", userName: "a@b.c", active: true })

    const res = await call("/Users/u1", { method: "DELETE" })
    expect(res.status).toBe(204)
    expect(await res.text()).toBe("")
  })

  test("PATCH deactivation works end to end through the router", async () => {
    const { call, directory } = await harness()
    directory.seed(TENANT, { id: "u1", userName: "a@b.c", active: true })

    const res = await call("/Users/u1", {
      method: "PATCH",
      headers: { "content-type": "application/scim+json" },
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "Replace", path: "active", value: "False" }],
      }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body["active"]).toBe(false)

    const stored = await directory.getUser(TENANT, "u1")
    expect(stored.ok && stored.value?.active).toBe(false)
  })

  test("a bad token is rejected at the HTTP edge too", async () => {
    const { call } = await harness()
    const res = await call("/Users", { token: "wrong" })
    expect(res.status).toBe(401)
  })

  test("no scimDirectory supplied → 501, whatever the tenant config says", async () => {
    const { call } = await harness({ withDirectory: false })
    const res = await call("/Users")
    expect(res.status).toBe(501)
    const body = (await res.json()) as Record<string, unknown>
    expect(String(body["detail"])).toContain("scimDirectory")
  })

  test("an id containing a URL-escaped character round-trips", async () => {
    const { call, directory } = await harness()
    directory.seed(TENANT, { id: "usr/1", userName: "a@b.c", active: true })

    const res = await call(`/Users/${encodeURIComponent("usr/1")}`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body["id"]).toBe("usr/1")
  })
})
