/**
 * SCIM PATCH normalization — conformance cases 8, 9, 10.
 *
 * The point of `SCIM-AD6` is that Okta and Entra spell the same intent
 * differently and the host should see neither spelling. These tests
 * assert the shapes converge, and that anything we cannot resolve is an
 * error rather than a silent no-op — a dropped operation is how
 * provisioning drifts undetected.
 */
import { describe, expect, test } from "bun:test"

import { normalizePatch } from "../../src/domain/scim/patch"
import type { ScimUserRecord } from "../../src/types/scim"

const CURRENT: ScimUserRecord = {
  id: "u1",
  userName: "alice@corp.example",
  active: true,
  externalId: "ext-1",
  displayName: "Alice Adams",
  name: { givenName: "Alice", familyName: "Adams" },
  emails: [
    { value: "alice@corp.example", type: "work", primary: true },
    { value: "alice@home.example", type: "home" },
  ],
}

const patchOp = (ops: unknown[]) => ({
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: ops,
})

function normalize(ops: unknown[], current: ScimUserRecord = CURRENT) {
  return normalizePatch(patchOp(ops), current)
}

describe("deactivation — the operation customers audit (cases 8, 9)", () => {
  test("Okta's pathless replace", async () => {
    const r = normalize([{ op: "replace", value: { active: false } }])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value).toEqual({ active: false })
  })

  test("Entra's path + capitalized op + STRING boolean", async () => {
    // Entra really does send "False" as a string. Rejecting it would
    // fail every Entra deprovisioning.
    const r = normalize([{ op: "Replace", path: "active", value: "False" }])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value).toEqual({ active: false })
  })

  test("all the spellings converge on one delta", async () => {
    const variants = [
      [{ op: "replace", value: { active: false } }],
      [{ op: "replace", path: "active", value: false }],
      [{ op: "Replace", path: "active", value: "False" }],
      [{ op: "REPLACE", path: "active", value: "false" }],
    ]
    for (const ops of variants) {
      const r = normalize(ops)
      expect(r.ok).toBe(true)
      if (r.ok) expect(r.value.active).toBe(false)
    }
  })

  test("reactivation works the same way", async () => {
    const r = normalize([{ op: "replace", path: "active", value: "True" }])
    expect(r.ok && r.value.active).toBe(true)
  })

  test("a non-boolean active is refused, not coerced to false", async () => {
    // Silently reading "yes" as false would deactivate a user nobody
    // asked to deactivate.
    const r = normalize([{ op: "replace", path: "active", value: "yes" }])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.scimType).toBe("invalidValue")
  })
})

describe("targeted multi-valued paths resolve against the record", () => {
  test('emails[type eq "work"].value upserts, preserving the others', async () => {
    const r = normalize([
      {
        op: "replace",
        path: 'emails[type eq "work"].value',
        value: "new@corp.example",
      },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    // The host receives a complete list, never a path expression.
    expect(r.value.emails).toEqual([
      { value: "new@corp.example", type: "work", primary: true },
      { value: "alice@home.example", type: "home" },
    ])
  })

  test("adding a type that does not exist yet appends it", async () => {
    const r = normalize([
      {
        op: "add",
        path: 'phoneNumbers[type eq "mobile"].value',
        value: "+15550100",
      },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.phoneNumbers).toEqual([
      { value: "+15550100", type: "mobile" },
    ])
  })

  test("removing one type keeps the rest", async () => {
    const r = normalize([
      { op: "remove", path: 'emails[type eq "home"].value' },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.emails).toEqual([
      { value: "alice@corp.example", type: "work", primary: true },
    ])
  })

  test("replacing the whole array is a replace, not a merge", async () => {
    const r = normalize([
      { op: "replace", path: "emails", value: [{ value: "only@x.example" }] },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.emails).toEqual([{ value: "only@x.example" }])
  })
})

describe("complex sub-attributes", () => {
  test("name.givenName merges with the existing name", async () => {
    const r = normalize([
      { op: "replace", path: "name.givenName", value: "Alicia" },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    // familyName survives — the host gets the resolved whole.
    expect(r.value.name).toEqual({ givenName: "Alicia", familyName: "Adams" })
  })

  test("a pathless op carrying a name object replaces it", async () => {
    const r = normalize([
      { op: "replace", value: { name: { givenName: "Al" } } },
    ])
    expect(r.ok && r.value.name).toEqual({ givenName: "Al" })
  })

  test("enterprise extension paths resolve", async () => {
    const r = normalize([
      {
        op: "replace",
        path:
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
        value: "Platform",
      },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.enterprise).toEqual({ department: "Platform" })
  })

  test("removing displayName clears it rather than leaving it", async () => {
    const r = normalize([{ op: "remove", path: "displayName" }])
    expect(r.ok && r.value.displayName).toBeNull()
  })
})

describe("multiple operations compose in order", () => {
  test("two ops in one request both land", async () => {
    const r = normalize([
      { op: "replace", path: "active", value: false },
      { op: "replace", path: "name.givenName", value: "Alicia" },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.active).toBe(false)
    expect(r.value.name?.givenName).toBe("Alicia")
  })

  test("successive edits to the same list compose", async () => {
    const r = normalize([
      { op: "replace", path: 'emails[type eq "work"].value', value: "a@x.io" },
      { op: "add", path: 'emails[type eq "other"].value', value: "b@x.io" },
    ])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.emails).toEqual([
      { value: "a@x.io", type: "work", primary: true },
      { value: "alice@home.example", type: "home" },
      { value: "b@x.io", type: "other" },
    ])
  })
})

describe("unsupported input is an error, never a silent drop (case 10)", () => {
  test("an unknown attribute path is rejected", async () => {
    const r = normalize([
      { op: "replace", path: "nickName", value: "Ally" },
    ])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.scimType).toBe("invalidPath")
    expect(r.error.status).toBe(400)
  })

  test("a non-type multi-valued filter is rejected", async () => {
    const r = normalize([
      {
        op: "replace",
        path: 'emails[primary eq true].value',
        value: "x@y.z",
      },
    ])
    expect(r.ok).toBe(false)
  })

  test("an unsupported op verb is rejected", async () => {
    const r = normalize([{ op: "increment", path: "active", value: 1 }])
    expect(r.ok).toBe(false)
  })

  test("removing userName is refused", async () => {
    const r = normalize([{ op: "remove", path: "userName" }])
    expect(r.ok).toBe(false)
  })

  test("a body with no Operations is rejected", async () => {
    const r = normalizePatch(
      { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"] },
      CURRENT,
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.scimType).toBe("invalidSyntax")
  })

  test("a wrong schema urn is rejected", async () => {
    const r = normalizePatch(
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        Operations: [{ op: "replace", value: { active: false } }],
      },
      CURRENT,
    )
    expect(r.ok).toBe(false)
  })

  test("lowercase 'operations' is accepted (smaller IdPs emit it)", async () => {
    const r = normalizePatch(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        operations: [{ op: "replace", value: { active: false } }],
      },
      CURRENT,
    )
    expect(r.ok && r.value.active).toBe(false)
  })

  test("a patch resolving to nothing is an error, not a no-op success", async () => {
    const r = normalizePatch(patchOp([]), CURRENT)
    expect(r.ok).toBe(false)
  })
})
