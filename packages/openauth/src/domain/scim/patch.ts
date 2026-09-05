/**
 * SCIM PATCH normalization (`SCIM-AD6`).
 *
 * `PATCH /Users/:id` carries a `PatchOp` whose `Operations` are the
 * worst-specified part of SCIM, and Okta and Entra spell the same intent
 * differently:
 *
 *     Okta:   { "op": "replace", "value": { "active": false } }
 *     Entra:  { "op": "Replace", "path": "active", "value": "False" }
 *     Entra:  { "op": "add", "path": "emails[type eq \"work\"].value", … }
 *
 * All three mean one thing to the host. This module resolves every
 * supported shape — pathless object merges, dotted sub-attribute paths,
 * multi-valued filter paths, the enterprise-extension URN prefix, and
 * Entra's habit of sending booleans as the strings `"True"` / `"False"`
 * — into a flat `ScimUserPatch` of fully resolved values.
 *
 * Resolution is done **against the current record**, which the caller
 * has already fetched (it needs it for 404 semantics anyway). That means
 * a targeted operation like `emails[type eq "work"].value` becomes a
 * complete `emails` array, so the host implements exactly one semantic:
 * present ⇒ set to this, `null` ⇒ clear, absent ⇒ leave alone. No merge
 * logic and no path parsing ever reaches the host.
 *
 * Two kinds of "we can't do that" are treated very differently:
 *
 *   - An attribute this Service Provider does not model at all (`title`,
 *     `nickName`, `locale`, …) is **skipped**. There is nowhere for it to
 *     go — `ScimUserPatch` has no field for it — so nothing drifts, and
 *     `parseUserWrite` already ignores the same attributes on POST/PUT.
 *     Rejecting them here would fail the whole request over an attribute
 *     we would have discarded anyway: Okta's default profile mappings
 *     push `title` in the *same* `PatchOp` as `active`, so a fatal
 *     unknown-attribute error takes the deactivation down with it, and
 *     Okta retries the identical payload forever.
 *   - A malformed operation on an attribute we **do** model (a
 *     non-boolean `active`, an unparseable path shape) stays an error.
 *     That one really would drift undetected.
 *
 * Pure: no I/O, no port access.
 */
import type {
  ScimGroupMember,
  ScimGroupPatch,
  ScimMultiValue,
  ScimName,
  ScimUserPatch,
  ScimUserRecord,
} from "../../types/scim"
import { err, ok, type Result } from "../../types/result"

import {
  parseMembers,
  SCIM_ENTERPRISE_SCHEMA,
  SCIM_PATCH_SCHEMA,
  type ScimValidationError,
} from "./resource"

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v)

/**
 * Entra sends booleans as the strings `"True"` / `"False"` on
 * `active`. Accepting those is not laxness for its own sake — rejecting
 * them would fail every Entra deprovisioning, which is the single
 * operation customers audit.
 */
function coerceBoolean(v: unknown): boolean | undefined {
  if (typeof v === "boolean") return v
  if (typeof v === "string") {
    const lowered = v.toLowerCase()
    if (lowered === "true") return true
    if (lowered === "false") return false
  }
  return undefined
}

const asString = (v: unknown): string | undefined =>
  typeof v === "string" ? v : undefined

/**
 * Strip the enterprise-extension URN prefix from a path, if present.
 *
 * Two shapes arrive. A qualified path
 * (`urn:…:enterprise:2.0:User:department`) carries the sub-attribute
 * after a colon. A **pathless** op instead uses the bare URN as an
 * object key, with the whole extension object as its value — and the
 * recursion in `applyOperation` then hands that URN here as a path of
 * its own. Matching only the colon-suffixed form missed the second case,
 * and the URN's `2.0` made the result look like a dotted path.
 */
function stripEnterprisePrefix(path: string): {
  path: string
  enterprise: boolean
} {
  if (path.toLowerCase() === SCIM_ENTERPRISE_SCHEMA.toLowerCase()) {
    return { path: "", enterprise: true }
  }
  const prefix = `${SCIM_ENTERPRISE_SCHEMA}:`
  if (path.toLowerCase().startsWith(prefix.toLowerCase())) {
    return { path: path.slice(prefix.length), enterprise: true }
  }
  const corePrefix = "urn:ietf:params:scim:schemas:core:2.0:user:"
  if (path.toLowerCase().startsWith(corePrefix)) {
    return { path: path.slice(corePrefix.length), enterprise: false }
  }
  return { path, enterprise: false }
}

/**
 * Parse a multi-valued filter path such as
 * `emails[type eq "work"].value` into its parts.
 */
function parseMultiValuedPath(
  path: string,
): { attribute: string; type: string; sub: string } | null {
  const m = /^([A-Za-z]+)\[\s*type\s+eq\s+"([^"]+)"\s*\]\.([A-Za-z]+)$/i.exec(
    path.trim(),
  )
  if (!m) return null
  return {
    attribute: (m[1] as string).toLowerCase(),
    type: m[2] as string,
    sub: (m[3] as string).toLowerCase(),
  }
}

/**
 * Upsert one entry into a multi-valued list, matching on `type`.
 *
 * Falls back to a single untyped entry when nothing matches by type. A
 * user created from a payload whose email carried no `type` would
 * otherwise gain a *second* email the first time Entra synced
 * `emails[type eq "work"].value` — the untyped entry can never match, so
 * every sync appends. Adopting the lone untyped entry (and labelling it)
 * is the interpretation that keeps one address for one person; with two
 * or more untyped entries there is no non-arbitrary choice, so we append.
 */
function upsertByType(
  current: ScimMultiValue[] | undefined,
  type: string,
  value: string,
): ScimMultiValue[] {
  const list = [...(current ?? [])]
  const byType = list.findIndex(
    (e) => (e.type ?? "").toLowerCase() === type.toLowerCase(),
  )
  if (byType >= 0) {
    list[byType] = { ...(list[byType] as ScimMultiValue), value }
    return list
  }
  const untyped = list.filter((e) => e.type === undefined)
  if (untyped.length === 1) {
    const idx = list.indexOf(untyped[0] as ScimMultiValue)
    list[idx] = { ...(list[idx] as ScimMultiValue), value, type }
    return list
  }
  list.push({ value, type })
  return list
}

const NAME_SUBS = new Set([
  "formatted",
  "familyname",
  "givenname",
  "middlename",
  "honorificprefix",
  "honorificsuffix",
])

const NAME_CANONICAL: Record<string, keyof ScimName> = {
  formatted: "formatted",
  familyname: "familyName",
  givenname: "givenName",
  middlename: "middleName",
  honorificprefix: "honorificPrefix",
  honorificsuffix: "honorificSuffix",
}

const ENTERPRISE_SUBS: Record<string, string> = {
  employeenumber: "employeeNumber",
  costcenter: "costCenter",
  organization: "organization",
  division: "division",
  department: "department",
}

type Draft = {
  patch: ScimUserPatch
  /** Working copies so successive ops in one request compose. */
  emails: ScimMultiValue[] | undefined
  phoneNumbers: ScimMultiValue[] | undefined
  name: ScimName | undefined
  enterprise: Record<string, unknown> | undefined
}

function invalidPath(detail: string): ScimValidationError {
  return { status: 400, scimType: "invalidPath", detail }
}

/**
 * The attribute is outside this Service Provider's model — skip the
 * operation rather than failing the request. See the note at the top of
 * this file on why unmodelled ≠ malformed.
 */
const SKIP = null

/** Apply one `{op, path, value}` to the working draft. */
function applyOperation(
  draft: Draft,
  op: string,
  rawPath: string | undefined,
  value: unknown,
): ScimValidationError | null {
  const operation = op.toLowerCase()
  if (
    operation !== "add" &&
    operation !== "replace" &&
    operation !== "remove"
  ) {
    return invalidPath(`unsupported PATCH op "${op}"`)
  }

  // --- Pathless op: the value is an object of attribute → new value.
  if (rawPath === undefined || rawPath.trim().length === 0) {
    if (operation === "remove") {
      return invalidPath('"remove" requires a path')
    }
    if (!isRecord(value)) {
      return invalidPath(
        'a PATCH operation without a path must carry an object value',
      )
    }
    for (const [k, v] of Object.entries(value)) {
      const nested = applyOperation(draft, operation, k, v)
      if (nested) return nested
    }
    return null
  }

  const { path: stripped, enterprise } = stripEnterprisePrefix(rawPath.trim())
  const removing = operation === "remove"

  // --- Multi-valued filter path: emails[type eq "work"].value
  const mv = parseMultiValuedPath(stripped)
  if (mv) {
    if (mv.attribute !== "emails" && mv.attribute !== "phonenumbers") {
      return SKIP // an unmodelled multi-valued attribute (ims, photos, …)
    }
    if (mv.sub !== "value") {
      return invalidPath(
        `only the ".value" sub-attribute of a multi-valued path is ` +
          `supported, got ".${mv.sub}"`,
      )
    }
    const key = mv.attribute === "emails" ? "emails" : "phoneNumbers"
    const current = mv.attribute === "emails" ? draft.emails : draft.phoneNumbers
    if (removing) {
      const filtered = (current ?? []).filter(
        (e) => (e.type ?? "").toLowerCase() !== mv.type.toLowerCase(),
      )
      if (key === "emails") draft.emails = filtered
      else draft.phoneNumbers = filtered
      draft.patch[key] = filtered.length > 0 ? filtered : null
      return null
    }
    const v = asString(value)
    if (v === undefined) {
      return {
        status: 400,
        scimType: "invalidValue",
        detail: `value for "${rawPath}" must be a string`,
      }
    }
    const next = upsertByType(current, mv.type, v)
    if (key === "emails") draft.emails = next
    else draft.phoneNumbers = next
    draft.patch[key] = next
    return null
  }

  if (stripped.includes("[")) {
    return invalidPath(
      `unsupported multi-valued path "${rawPath}"; only ` +
        `<attr>[type eq "…"].value is supported`,
    )
  }

  const segments = stripped.split(".")
  const head = (segments[0] ?? "").toLowerCase()
  const sub = segments[1]?.toLowerCase()
  if (segments.length > 2) {
    return invalidPath(`path "${rawPath}" is too deeply nested`)
  }

  // --- Enterprise extension sub-attributes.
  if (enterprise) {
    // Bare URN key: the value is the whole extension object, so fan out
    // over its keys as if each had been sent as a qualified path.
    if (stripped === "") {
      if (removing) {
        draft.enterprise = undefined
        draft.patch.enterprise = null
        return null
      }
      if (!isRecord(value)) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: "the enterprise extension requires an object value",
        }
      }
      for (const [k, v] of Object.entries(value)) {
        const nested = applyOperation(
          draft,
          operation,
          `${SCIM_ENTERPRISE_SCHEMA}:${k}`,
          v,
        )
        if (nested) return nested
      }
      return null
    }
    const canonical = ENTERPRISE_SUBS[head]
    if (head === "manager") {
      const current = { ...(draft.enterprise ?? {}) }
      if (removing) delete current["manager"]
      else {
        const v = isRecord(value)
          ? { value: asString(value["value"]), displayName: asString(value["displayName"]) }
          : { value: asString(value) }
        current["manager"] = v
      }
      draft.enterprise = current
      draft.patch.enterprise = current as ScimUserPatch["enterprise"]
      return null
    }
    if (!canonical) {
      return SKIP // unmodelled enterprise sub-attribute
    }
    const current = { ...(draft.enterprise ?? {}) }
    if (removing) delete current[canonical]
    else {
      const v = asString(value)
      if (v === undefined) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: `value for "${rawPath}" must be a string`,
        }
      }
      current[canonical] = v
    }
    draft.enterprise = current
    draft.patch.enterprise = current as ScimUserPatch["enterprise"]
    return null
  }

  // --- name.<sub>
  if (head === "name") {
    if (sub === undefined) {
      if (removing) {
        draft.name = undefined
        draft.patch.name = null
        return null
      }
      if (!isRecord(value)) {
        return invalidPath('"name" requires an object value')
      }
      // RFC 7644 §3.5.2.1: `add` on a complex attribute adds the given
      // sub-attributes, leaving the others in place. Only `replace`
      // substitutes the whole thing. Treating both as a replace silently
      // cleared familyName whenever an IdP sent givenName alone.
      const merged: ScimName =
        operation === "add" ? { ...(draft.name ?? {}) } : {}
      for (const [k, v] of Object.entries(value)) {
        const canonical = NAME_CANONICAL[k.toLowerCase()]
        const s = asString(v)
        if (canonical && s !== undefined) merged[canonical] = s
      }
      draft.name = merged
      draft.patch.name = Object.keys(merged).length > 0 ? merged : null
      return null
    }
    if (!NAME_SUBS.has(sub)) {
      return invalidPath(`name sub-attribute "${sub}" is not supported`)
    }
    const canonical = NAME_CANONICAL[sub] as keyof ScimName
    const merged: ScimName = { ...(draft.name ?? {}) }
    if (removing) delete merged[canonical]
    else {
      const s = asString(value)
      if (s === undefined) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: `value for "${rawPath}" must be a string`,
        }
      }
      merged[canonical] = s
    }
    draft.name = merged
    draft.patch.name = Object.keys(merged).length > 0 ? merged : null
    return null
  }

  if (sub !== undefined) {
    return SKIP // a sub-attribute of something we do not model
  }

  // --- Simple top-level attributes.
  switch (head) {
    case "active": {
      if (removing) {
        return invalidPath('"active" cannot be removed; set it to false')
      }
      const b = coerceBoolean(value)
      if (b === undefined) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: `"active" must be a boolean, got ${JSON.stringify(value)}`,
        }
      }
      draft.patch.active = b
      return null
    }
    case "username": {
      if (removing) {
        return invalidPath('"userName" cannot be removed')
      }
      const s = asString(value)
      if (s === undefined || s.length === 0) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: '"userName" must be a non-empty string',
        }
      }
      draft.patch.userName = s
      return null
    }
    case "externalid": {
      draft.patch.externalId = removing ? null : (asString(value) ?? null)
      return null
    }
    case "displayname": {
      draft.patch.displayName = removing ? null : (asString(value) ?? null)
      return null
    }
    case "emails":
    case "phonenumbers": {
      const key = head === "emails" ? "emails" : "phoneNumbers"
      if (removing) {
        if (key === "emails") draft.emails = undefined
        else draft.phoneNumbers = undefined
        draft.patch[key] = null
        return null
      }
      if (!Array.isArray(value)) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: `"${head}" must be an array`,
        }
      }
      const list: ScimMultiValue[] = []
      for (const entry of value) {
        if (!isRecord(entry)) continue
        const v = asString(entry["value"])
        if (v === undefined) continue
        const type = asString(entry["type"])
        const primary = entry["primary"]
        list.push({
          value: v,
          ...(type !== undefined ? { type } : {}),
          ...(typeof primary === "boolean" ? { primary } : {}),
        })
      }
      if (key === "emails") draft.emails = list
      else draft.phoneNumbers = list
      draft.patch[key] = list.length > 0 ? list : null
      return null
    }
    default:
      return SKIP // unmodelled attribute: title, nickName, locale, …
  }
}

/**
 * Normalize a `PatchOp` body into a `ScimUserPatch`, resolved against
 * `current`.
 */
export function normalizePatch(
  body: unknown,
  current: ScimUserRecord,
): Result<ScimUserPatch, ScimValidationError> {
  if (!isRecord(body)) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: "request body must be a JSON object",
    })
  }

  const schemas = body["schemas"]
  if (
    Array.isArray(schemas) &&
    !schemas.some(
      (s) =>
        typeof s === "string" &&
        s.toLowerCase() === SCIM_PATCH_SCHEMA.toLowerCase(),
    )
  ) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: `PATCH body must declare the ${SCIM_PATCH_SCHEMA} schema`,
    })
  }

  // Okta and Entra both send "Operations"; accept the lowercase spelling
  // too, which some smaller IdPs emit.
  const rawOps = body["Operations"] ?? body["operations"]
  if (!Array.isArray(rawOps) || rawOps.length === 0) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: "PATCH body must carry a non-empty Operations array",
    })
  }

  const draft: Draft = {
    patch: {},
    emails: current.emails ? [...current.emails] : undefined,
    phoneNumbers: current.phoneNumbers ? [...current.phoneNumbers] : undefined,
    name: current.name ? { ...current.name } : undefined,
    enterprise: current.enterprise
      ? ({ ...current.enterprise } as Record<string, unknown>)
      : undefined,
  }

  for (const raw of rawOps) {
    if (!isRecord(raw)) {
      return err({
        status: 400,
        scimType: "invalidSyntax",
        detail: "each PATCH operation must be an object",
      })
    }
    const op = asString(raw["op"])
    if (op === undefined) {
      return err({
        status: 400,
        scimType: "invalidSyntax",
        detail: "each PATCH operation must carry an op",
      })
    }
    const failure = applyOperation(
      draft,
      op,
      asString(raw["path"]),
      raw["value"],
    )
    if (failure) return err(failure)
  }

  if (Object.keys(draft.patch).length === 0) {
    return err({
      status: 400,
      scimType: "invalidValue",
      detail: "PATCH resolved to no changes",
    })
  }

  return ok(draft.patch)
}


/**
 * Extract the member id from a `members[value eq "…"]` path.
 *
 * Note there is no `.sub` suffix here, unlike the user-side
 * `emails[type eq "work"].value` — Okta targets the whole member entry
 * for removal, not one of its sub-attributes.
 */
function parseMemberFilterPath(path: string): string | null {
  const m = /^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$/i.exec(path.trim())
  return m ? (m[1] as string) : null
}

/**
 * Normalize a group `PatchOp`.
 *
 * Membership deliberately keeps the client's intent rather than being
 * resolved to a final list (`SCIM-AD9`): "add one member" stays an add,
 * so a host with a 20,000-member group issues one insert instead of
 * rewriting the whole membership.
 *
 * A full replace still wins when one is present — subsequent
 * adds/removes in the same request are folded into the replacement list,
 * so the host never receives `members` alongside `addMembers` /
 * `removeMembers` and needs no ordering rules of its own.
 *
 * Shapes handled:
 *
 *     Okta:  {op:"add",     path:"members", value:[{value:"u1"}]}
 *     Okta:  {op:"remove",  path:"members[value eq \"u1\"]"}
 *     Entra: {op:"remove",  path:"members", value:[{value:"u1"}]}
 *     both:  {op:"replace", path:"members", value:[…]}
 *     both:  {op:"replace", path:"displayName", value:"New"}
 *     both:  {op:"replace", value:{displayName:"New"}}
 */
export function normalizeGroupPatch(
  body: unknown,
): Result<ScimGroupPatch, ScimValidationError> {
  if (!isRecord(body)) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: "request body must be a JSON object",
    })
  }
  const schemas = body["schemas"]
  if (
    Array.isArray(schemas) &&
    !schemas.some(
      (s) =>
        typeof s === "string" &&
        s.toLowerCase() === SCIM_PATCH_SCHEMA.toLowerCase(),
    )
  ) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: `PATCH body must declare the ${SCIM_PATCH_SCHEMA} schema`,
    })
  }

  const rawOps = body["Operations"] ?? body["operations"]
  if (!Array.isArray(rawOps) || rawOps.length === 0) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: "PATCH body must carry a non-empty Operations array",
    })
  }

  const patch: ScimGroupPatch = {}
  const added: ScimGroupMember[] = []
  const removed: string[] = []
  /** Non-null once a full replace has been seen. */
  let replacement: ScimGroupMember[] | null = null

  const applyAdd = (members: ScimGroupMember[]) => {
    if (replacement !== null) {
      for (const m of members) {
        if (!replacement.some((e) => e.value === m.value)) replacement.push(m)
      }
      return
    }
    for (const m of members) {
      if (!added.some((e) => e.value === m.value)) added.push(m)
    }
  }
  const applyRemove = (ids: string[]) => {
    if (replacement !== null) {
      replacement = replacement.filter((e) => !ids.includes(e.value))
      return
    }
    for (const id of ids) if (!removed.includes(id)) removed.push(id)
  }

  const handle = (
    op: string,
    rawPath: string | undefined,
    value: unknown,
  ): ScimValidationError | null => {
    const operation = op.toLowerCase()
    if (
      operation !== "add" &&
      operation !== "replace" &&
      operation !== "remove"
    ) {
      return invalidPath(`unsupported PATCH op "${op}"`)
    }

    // Pathless: an object of attribute → value.
    if (rawPath === undefined || rawPath.trim().length === 0) {
      if (!isRecord(value)) {
        return invalidPath(
          "a PATCH operation without a path must carry an object value",
        )
      }
      for (const [k, v] of Object.entries(value)) {
        const nested = handle(operation, k, v)
        if (nested) return nested
      }
      return null
    }

    const path = rawPath.trim()

    const targeted = parseMemberFilterPath(path)
    if (targeted !== null) {
      if (operation !== "remove") {
        return invalidPath(
          `only "remove" is supported with a members[value eq …] path`,
        )
      }
      applyRemove([targeted])
      return null
    }

    if (path.toLowerCase() === "members") {
      if (operation === "remove" && value === undefined) {
        // "remove all members" — a replace with an empty list.
        replacement = []
        return null
      }
      const members = parseMembers(value)
      if (members === undefined) {
        return {
          status: 400,
          scimType: "invalidValue",
          detail: '"members" must be an array of {value} entries',
        }
      }
      if (operation === "add") applyAdd(members)
      else if (operation === "remove") applyRemove(members.map((m) => m.value))
      else replacement = [...members]
      return null
    }

    if (path.includes("[")) {
      return invalidPath(
        `unsupported path "${rawPath}"; only members[value eq "…"] is ` +
          `supported for targeted membership changes`,
      )
    }

    switch (path.toLowerCase()) {
      case "displayname": {
        if (operation === "remove") {
          return invalidPath('"displayName" cannot be removed')
        }
        const s = asString(value)
        if (s === undefined || s.length === 0) {
          return {
            status: 400,
            scimType: "invalidValue",
            detail: '"displayName" must be a non-empty string',
          }
        }
        patch.displayName = s
        return null
      }
      case "externalid": {
        patch.externalId =
          operation === "remove" ? null : (asString(value) ?? null)
        return null
      }
      default:
        return invalidPath(
          `attribute "${rawPath}" is not patchable on a Group`,
        )
    }
  }

  for (const raw of rawOps) {
    if (!isRecord(raw)) {
      return err({
        status: 400,
        scimType: "invalidSyntax",
        detail: "each PATCH operation must be an object",
      })
    }
    const op = asString(raw["op"])
    if (op === undefined) {
      return err({
        status: 400,
        scimType: "invalidSyntax",
        detail: "each PATCH operation must carry an op",
      })
    }
    const failure = handle(op, asString(raw["path"]), raw["value"])
    if (failure) return err(failure)
  }

  // A replace subsumes the incremental fields, so the host only ever
  // sees one membership shape.
  if (replacement !== null) patch.members = replacement
  else {
    if (added.length > 0) patch.addMembers = added
    if (removed.length > 0) patch.removeMembers = removed
  }

  if (Object.keys(patch).length === 0) {
    return err({
      status: 400,
      scimType: "invalidValue",
      detail: "PATCH resolved to no changes",
    })
  }
  return ok(patch)
}
