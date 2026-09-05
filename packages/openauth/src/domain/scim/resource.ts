/**
 * SCIM resource shapes — validation in, serialization out, and the
 * error envelope.
 *
 * RFC 7643 defines the User schema; RFC 7644 defines the message
 * envelopes. Both are picky in ways that are easy to get subtly wrong
 * and that Okta's validator checks, so the details here are asserted in
 * tests rather than assumed:
 *
 *   - `status` in an Error is a **string**, not a number.
 *   - `ListResponse` uses `Resources` with a capital R.
 *   - `startIndex` is **1-based**.
 *   - `meta.location` must be an absolute URL; Okta reads it.
 *
 * Pure: no I/O, no port access.
 */
import type {
  ScimEnterpriseUser,
  ScimGroupMember,
  ScimGroupRecord,
  ScimGroupWrite,
  ScimMultiValue,
  ScimName,
  ScimUserRecord,
  ScimUserWrite,
} from "../../types/scim"
import { err, ok, type Result } from "../../types/result"

export const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
export const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
export const SCIM_ENTERPRISE_SCHEMA =
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
export const SCIM_LIST_SCHEMA =
  "urn:ietf:params:scim:api:messages:2.0:ListResponse"
export const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
export const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

/** RFC 7644 §3.12 `scimType` values we emit. */
export type ScimErrorType =
  | "invalidFilter"
  | "invalidPath"
  | "invalidSyntax"
  | "invalidValue"
  | "mutability"
  | "noTarget"
  | "uniqueness"
  | "tooMany"

export type ScimValidationError = {
  status: number
  detail: string
  scimType?: ScimErrorType
}

/** RFC 7644 §3.12 error envelope. */
export function scimErrorBody(
  status: number,
  detail: string,
  scimType?: ScimErrorType,
): Record<string, unknown> {
  return {
    schemas: [SCIM_ERROR_SCHEMA],
    // A string, per the RFC's own examples — a number here is a common
    // implementation bug and Okta's validator notices.
    status: String(status),
    ...(scimType !== undefined ? { scimType } : {}),
    detail,
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v)

const asString = (v: unknown): string | undefined =>
  typeof v === "string" && v.length > 0 ? v : undefined

function parseName(v: unknown): ScimName | undefined {
  if (!isRecord(v)) return undefined
  const out: ScimName = {}
  for (const k of [
    "formatted",
    "familyName",
    "givenName",
    "middleName",
    "honorificPrefix",
    "honorificSuffix",
  ] as const) {
    const s = asString(v[k])
    if (s !== undefined) out[k] = s
  }
  return Object.keys(out).length > 0 ? out : undefined
}

function parseMultiValues(v: unknown): ScimMultiValue[] | undefined {
  if (!Array.isArray(v)) return undefined
  const out: ScimMultiValue[] = []
  for (const entry of v) {
    if (!isRecord(entry)) continue
    const value = asString(entry["value"])
    if (value === undefined) continue
    const type = asString(entry["type"])
    const primary = entry["primary"]
    out.push({
      value,
      ...(type !== undefined ? { type } : {}),
      ...(typeof primary === "boolean" ? { primary } : {}),
    })
  }
  return out.length > 0 ? out : undefined
}

function parseEnterprise(v: unknown): ScimEnterpriseUser | undefined {
  if (!isRecord(v)) return undefined
  const out: ScimEnterpriseUser = {}
  for (const k of [
    "employeeNumber",
    "costCenter",
    "organization",
    "division",
    "department",
  ] as const) {
    const s = asString(v[k])
    if (s !== undefined) out[k] = s
  }
  const mgr = v["manager"]
  if (isRecord(mgr)) {
    const value = asString(mgr["value"])
    const displayName = asString(mgr["displayName"])
    if (value !== undefined || displayName !== undefined) {
      out.manager = {
        ...(value !== undefined ? { value } : {}),
        ...(displayName !== undefined ? { displayName } : {}),
      }
    }
  }
  return Object.keys(out).length > 0 ? out : undefined
}

/**
 * Validate a `POST` / `PUT` user payload into a `ScimUserWrite`.
 *
 * Unknown attributes are ignored rather than rejected: SCIM clients send
 * plenty the spec allows and we do not model, and failing the whole
 * provisioning run over an extra field would be hostile. The two
 * exceptions are hard errors — a missing `userName`, which leaves the
 * record unidentifiable, and `password`, which we refuse to handle at
 * all rather than accept and drop.
 */
export function parseUserWrite(
  body: unknown,
): Result<ScimUserWrite, ScimValidationError> {
  if (!isRecord(body)) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: "request body must be a JSON object",
    })
  }

  if (body["password"] !== undefined) {
    return err({
      status: 400,
      scimType: "invalidValue",
      detail:
        "this Service Provider does not accept 'password' over SCIM; " +
        "credentials are managed by the authentication methods, not the " +
        "directory feed",
    })
  }

  const userName = asString(body["userName"])
  if (userName === undefined) {
    return err({
      status: 400,
      scimType: "invalidValue",
      detail: "userName is required and must be a non-empty string",
    })
  }

  const activeRaw = body["active"]
  if (activeRaw !== undefined && typeof activeRaw !== "boolean") {
    return err({
      status: 400,
      scimType: "invalidValue",
      detail: "active must be a boolean",
    })
  }

  const externalId = asString(body["externalId"])
  const displayName = asString(body["displayName"])
  const name = parseName(body["name"])
  const emails = parseMultiValues(body["emails"])
  const phoneNumbers = parseMultiValues(body["phoneNumbers"])
  const enterprise = parseEnterprise(body[SCIM_ENTERPRISE_SCHEMA])

  return ok({
    userName,
    // SCIM defaults `active` to true on create. Resolving the default
    // here keeps the semantics in one place instead of in every host.
    active: activeRaw === undefined ? true : activeRaw,
    ...(externalId !== undefined ? { externalId } : {}),
    ...(displayName !== undefined ? { displayName } : {}),
    ...(name !== undefined ? { name } : {}),
    ...(emails !== undefined ? { emails } : {}),
    ...(phoneNumbers !== undefined ? { phoneNumbers } : {}),
    ...(enterprise !== undefined ? { enterprise } : {}),
  })
}

const iso = (ms: number | undefined): string | undefined =>
  ms === undefined ? undefined : new Date(ms).toISOString()

/** Serialize a host record into a SCIM User resource. */
export function serializeUser(
  user: ScimUserRecord,
  baseUrl: string,
): Record<string, unknown> {
  const schemas = [SCIM_USER_SCHEMA]
  if (user.enterprise !== undefined) schemas.push(SCIM_ENTERPRISE_SCHEMA)

  const created = iso(user.createdAt)
  const lastModified = iso(user.updatedAt)

  return {
    schemas,
    id: user.id,
    ...(user.externalId !== undefined ? { externalId: user.externalId } : {}),
    userName: user.userName,
    ...(user.name !== undefined ? { name: user.name } : {}),
    ...(user.displayName !== undefined
      ? { displayName: user.displayName }
      : {}),
    ...(user.emails !== undefined ? { emails: user.emails } : {}),
    ...(user.phoneNumbers !== undefined
      ? { phoneNumbers: user.phoneNumbers }
      : {}),
    active: user.active,
    ...(user.enterprise !== undefined
      ? { [SCIM_ENTERPRISE_SCHEMA]: user.enterprise }
      : {}),
    meta: {
      resourceType: "User",
      ...(created !== undefined ? { created } : {}),
      ...(lastModified !== undefined ? { lastModified } : {}),
      location: `${baseUrl}/Users/${encodeURIComponent(user.id)}`,
    },
  }
}

/** RFC 7644 §3.4.2 ListResponse. */
export function serializeList(
  users: ScimUserRecord[],
  totalResults: number,
  startIndex: number,
  baseUrl: string,
): Record<string, unknown> {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults,
    startIndex,
    itemsPerPage: users.length,
    // Capital R — the spec's own casing, and a frequent interop bug.
    Resources: users.map((u) => serializeUser(u, baseUrl)),
  }
}

function parseMembers(v: unknown): ScimGroupMember[] | undefined {
  // Some IdPs send a bare object where the spec wants an array.
  const list = Array.isArray(v) ? v : isRecord(v) ? [v] : undefined
  if (list === undefined) return undefined
  const out: ScimGroupMember[] = []
  for (const entry of list) {
    if (!isRecord(entry)) continue
    const value = asString(entry["value"])
    if (value === undefined) continue
    const display = asString(entry["display"])
    out.push({ value, ...(display !== undefined ? { display } : {}) })
  }
  return out
}

export { parseMembers }

/** Validate a `POST` / `PUT` group payload. */
export function parseGroupWrite(
  body: unknown,
): Result<ScimGroupWrite, ScimValidationError> {
  if (!isRecord(body)) {
    return err({
      status: 400,
      scimType: "invalidSyntax",
      detail: "request body must be a JSON object",
    })
  }
  const displayName = asString(body["displayName"])
  if (displayName === undefined) {
    return err({
      status: 400,
      scimType: "invalidValue",
      detail: "displayName is required and must be a non-empty string",
    })
  }
  const externalId = asString(body["externalId"])
  const members = parseMembers(body["members"])
  return ok({
    displayName,
    ...(externalId !== undefined ? { externalId } : {}),
    ...(members !== undefined ? { members } : {}),
  })
}

/** Serialize a host group record into a SCIM Group resource. */
export function serializeGroup(
  group: ScimGroupRecord,
  baseUrl: string,
): Record<string, unknown> {
  const created = iso(group.createdAt)
  const lastModified = iso(group.updatedAt)
  return {
    schemas: [SCIM_GROUP_SCHEMA],
    id: group.id,
    ...(group.externalId !== undefined
      ? { externalId: group.externalId }
      : {}),
    displayName: group.displayName,
    // Omitted entirely when the host did not load membership — `[]`
    // would tell the client the group has been emptied.
    ...(group.members !== undefined
      ? {
          members: group.members.map((m) => ({
            value: m.value,
            ...(m.display !== undefined ? { display: m.display } : {}),
            $ref: `${baseUrl}/Users/${encodeURIComponent(m.value)}`,
            type: "User",
          })),
        }
      : {}),
    meta: {
      resourceType: "Group",
      ...(created !== undefined ? { created } : {}),
      ...(lastModified !== undefined ? { lastModified } : {}),
      location: `${baseUrl}/Groups/${encodeURIComponent(group.id)}`,
    },
  }
}

export function serializeGroupList(
  groups: ScimGroupRecord[],
  totalResults: number,
  startIndex: number,
  baseUrl: string,
): Record<string, unknown> {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults,
    startIndex,
    itemsPerPage: groups.length,
    Resources: groups.map((g) => serializeGroup(g, baseUrl)),
  }
}
