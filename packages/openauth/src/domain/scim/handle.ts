/**
 * SCIM request dispatch — the whole protocol surface, framework-free.
 *
 * The HTTP layer parses the request into plain data and applies the
 * result; every decision (auth, routing, validation, status codes)
 * happens here, so the entire SCIM surface is testable without Hono.
 * Same shape as `dispatchMethod`.
 *
 * Ordering is deliberate and security-relevant: authenticate before
 * routing, so an unauthenticated caller cannot probe which endpoints
 * exist; and distinguish "wrong token" (401) from "SCIM not enabled for
 * this tenant" (403) without ever emitting a 404 that would confirm
 * whether a tenant exists.
 */
import { timingSafeEqualStr } from "../crypto"
import { hashClientSecret } from "../token"

import type { ScimDirectory } from "../../ports/scim-directory"
import type { Result } from "../../types/result"
import type {
  ScimConfig,
  ScimGroupRecord,
  ScimUserRecord,
  ScimUserWrite,
} from "../../types/scim"
import type { TenantContext } from "../../types/tenant"

import { resourceTypes, schemas, serviceProviderConfig } from "./discovery"
import {
  GROUP_FILTER_ATTRIBUTES,
  parseScimFilter,
  SUPPORTED_FILTER_HELP,
  USER_FILTER_ATTRIBUTES,
} from "./filter"
import { normalizeGroupPatch, normalizePatch } from "./patch"
import {
  parseGroupWrite,
  parseUserWrite,
  scimErrorBody,
  serializeGroup,
  serializeGroupList,
  serializeList,
  serializeUser,
  type ScimErrorType,
} from "./resource"

/** Default page size when the client does not ask for one. */
const DEFAULT_PAGE_SIZE = 100
/**
 * Ceiling on `maxPageSize`, whatever a tenant configures. A SCIM client
 * controls `count`, so an unbounded value would let it ask the host for
 * an arbitrarily large read.
 */
const PAGE_SIZE_CEILING = 500

export type ScimResponse = {
  status: number
  /** `null` for 204. Serialized as `application/scim+json` by the caller. */
  body: Record<string, unknown> | null
}

export type ScimRequestInput = {
  tenant: TenantContext
  /** Upper-case HTTP method. */
  method: string
  /** Path **within** the SCIM mount, e.g. `"/Users/abc"`. */
  path: string
  query: URLSearchParams
  /** Parsed JSON body, or `null` for bodiless methods / unparseable input. */
  body: unknown
  /** Raw `Authorization` header value. */
  authorization: string | null
  /** Absolute base URL of the SCIM mount, e.g. `https://idp.example/scim/v2`. */
  baseUrl: string
  directory: ScimDirectory
}

const fail = (
  status: number,
  detail: string,
  scimType?: ScimErrorType,
): ScimResponse => ({
  status,
  body: scimErrorBody(status, detail, scimType),
})

/**
 * Map a host-returned `AuthError` onto a SCIM response.
 *
 * `conflict` is the one the host is expected to raise deliberately;
 * everything else becomes a 500, which SCIM clients retry. That is the
 * right outcome for a transient host failure — reporting success for a
 * write that did not happen is how deprovisioning silently fails.
 */
function fromPortError(error: {
  code: string
  description: string
  attribute?: string
}): ScimResponse {
  if (error.code === "conflict") {
    return fail(409, error.description, "uniqueness")
  }
  return fail(500, "the directory backing this endpoint failed the request")
}

function unwrap<T>(r: Result<T>): { value: T } | { response: ScimResponse } {
  if (r.ok) return { value: r.value }
  return { response: fromPortError(r.error as never) }
}

/** Constant-time bearer check against this tenant's configured token. */
async function authenticate(
  scim: ScimConfig | undefined,
  authorization: string | null,
): Promise<ScimResponse | null> {
  if (!scim || scim.enabled !== true) {
    // 403, never 404: a 404 here would let an unauthenticated caller
    // probe which tenants exist.
    return fail(403, "SCIM provisioning is not enabled for this tenant")
  }
  const prefix = "bearer "
  if (
    authorization === null ||
    !authorization.toLowerCase().startsWith(prefix)
  ) {
    return fail(401, "a Bearer token is required")
  }
  const presented = authorization.slice(prefix.length).trim()
  if (presented.length === 0) return fail(401, "a Bearer token is required")

  const hashed = await hashClientSecret(presented)
  if (!timingSafeEqualStr(hashed, scim.tokenHash)) {
    return fail(401, "invalid Bearer token")
  }
  return null
}

/** `/Users/<id>` → the decoded id; `/Users` → null. */
function userIdFrom(path: string): string | null {
  const m = /^\/Users\/(.+)$/.exec(path)
  if (!m) return null
  try {
    return decodeURIComponent(m[1] as string)
  } catch {
    return m[1] as string
  }
}

function clampPaging(
  query: URLSearchParams,
  maxPageSize: number,
): { startIndex: number; count: number } {
  const rawStart = Number(query.get("startIndex") ?? "1")
  // RFC 7644 §3.4.2.4: 1-based, and a value < 1 is interpreted as 1.
  const startIndex =
    Number.isFinite(rawStart) && rawStart >= 1 ? Math.floor(rawStart) : 1

  const rawCount = query.get("count")
  if (rawCount === null) return { startIndex, count: maxPageSize }
  const parsed = Number(rawCount)
  if (!Number.isFinite(parsed) || parsed < 0) {
    return { startIndex, count: maxPageSize }
  }
  return { startIndex, count: Math.min(Math.floor(parsed), maxPageSize) }
}

async function listUsers(
  input: ScimRequestInput,
  maxPageSize: number,
): Promise<ScimResponse> {
  const filter = parseScimFilter(
    input.query.get("filter"),
    USER_FILTER_ATTRIBUTES,
  )
  if (!filter.ok) {
    return fail(400, filter.error.detail, "invalidFilter")
  }
  const { startIndex, count } = clampPaging(input.query, maxPageSize)

  const page = await input.directory.findUsers(input.tenant.id, {
    ...(filter.value !== undefined ? { filter: filter.value } : {}),
    startIndex,
    count,
  })
  const r = unwrap(page)
  if ("response" in r) return r.response

  return {
    status: 200,
    body: serializeList(
      r.value.resources,
      r.value.totalResults,
      startIndex,
      input.baseUrl,
    ),
  }
}

async function createUser(input: ScimRequestInput): Promise<ScimResponse> {
  const parsed = parseUserWrite(input.body)
  if (!parsed.ok) {
    return fail(parsed.error.status, parsed.error.detail, parsed.error.scimType)
  }
  const created = await input.directory.createUser(
    input.tenant.id,
    parsed.value,
  )
  const r = unwrap(created)
  if ("response" in r) return r.response
  return { status: 201, body: serializeUser(r.value, input.baseUrl) }
}

async function loadUser(
  input: ScimRequestInput,
  id: string,
): Promise<{ user: ScimUserRecord } | { response: ScimResponse }> {
  const found = await input.directory.getUser(input.tenant.id, id)
  const r = unwrap(found)
  if ("response" in r) return r
  if (r.value === null) {
    return { response: fail(404, `no User with id "${id}"`) }
  }
  return { user: r.value }
}

async function replaceUser(
  input: ScimRequestInput,
  id: string,
): Promise<ScimResponse> {
  const existing = await loadUser(input, id)
  if ("response" in existing) return existing.response

  const parsed = parseUserWrite(input.body)
  if (!parsed.ok) {
    return fail(parsed.error.status, parsed.error.detail, parsed.error.scimType)
  }
  const write: ScimUserWrite = parsed.value
  const replaced = await input.directory.replaceUser(
    input.tenant.id,
    id,
    write,
  )
  const r = unwrap(replaced)
  if ("response" in r) return r.response
  return { status: 200, body: serializeUser(r.value, input.baseUrl) }
}

async function patchUser(
  input: ScimRequestInput,
  id: string,
): Promise<ScimResponse> {
  // The current record is needed for 404 semantics anyway, so resolving
  // targeted patch paths against it costs nothing extra.
  const existing = await loadUser(input, id)
  if ("response" in existing) return existing.response

  const normalized = normalizePatch(input.body, existing.user)
  if (!normalized.ok) {
    return fail(
      normalized.error.status,
      normalized.error.detail,
      normalized.error.scimType,
    )
  }
  const patched = await input.directory.patchUser(
    input.tenant.id,
    id,
    normalized.value,
  )
  const r = unwrap(patched)
  if ("response" in r) return r.response
  return { status: 200, body: serializeUser(r.value, input.baseUrl) }
}

async function deleteUser(
  input: ScimRequestInput,
  id: string,
): Promise<ScimResponse> {
  const existing = await loadUser(input, id)
  if ("response" in existing) return existing.response

  const deleted = await input.directory.deleteUser(input.tenant.id, id)
  const r = unwrap(deleted)
  if ("response" in r) return r.response
  return { status: 204, body: null }
}


/**
 * Groups are optional as a set on the port — a host that only needs user
 * provisioning implements none of them and gets a clean 501 rather than
 * a runtime failure mid-push.
 */
function groupsSupported(d: ScimRequestInput["directory"]): boolean {
  return (
    typeof d.getGroup === "function" &&
    typeof d.findGroups === "function" &&
    typeof d.createGroup === "function" &&
    typeof d.replaceGroup === "function" &&
    typeof d.patchGroup === "function" &&
    typeof d.deleteGroup === "function"
  )
}

/** `excludedAttributes=members` — Okta sets it while enumerating. */
function excludesMembers(query: URLSearchParams): boolean {
  const raw = query.get("excludedAttributes")
  if (raw === null) return false
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .includes("members")
}

async function loadGroup(
  input: ScimRequestInput,
  id: string,
): Promise<{ group: ScimGroupRecord } | { response: ScimResponse }> {
  const found = await input.directory.getGroup!(input.tenant.id, id)
  const r = unwrap(found)
  if ("response" in r) return r
  if (r.value === null) {
    return { response: fail(404, `no Group with id "${id}"`) }
  }
  return { group: r.value }
}

async function handleGroups(
  input: ScimRequestInput,
  path: string,
  method: string,
  maxPageSize: number,
): Promise<ScimResponse> {
  if (!groupsSupported(input.directory)) {
    return fail(
      501,
      "Group provisioning is not implemented by this Service Provider",
    )
  }

  if (path === "/Groups" || path === "/Groups/") {
    if (method === "GET") {
      const filter = parseScimFilter(
        input.query.get("filter"),
        GROUP_FILTER_ATTRIBUTES,
      )
      if (!filter.ok) return fail(400, filter.error.detail, "invalidFilter")
      const { startIndex, count } = clampPaging(input.query, maxPageSize)
      const page = await input.directory.findGroups!(input.tenant.id, {
        ...(filter.value !== undefined ? { filter: filter.value } : {}),
        startIndex,
        count,
        excludeMembers: excludesMembers(input.query),
      })
      const r = unwrap(page)
      if ("response" in r) return r.response
      return {
        status: 200,
        body: serializeGroupList(
          r.value.resources,
          r.value.totalResults,
          startIndex,
          input.baseUrl,
        ),
      }
    }
    if (method === "POST") {
      const parsed = parseGroupWrite(input.body)
      if (!parsed.ok) {
        return fail(
          parsed.error.status,
          parsed.error.detail,
          parsed.error.scimType,
        )
      }
      const created = await input.directory.createGroup!(
        input.tenant.id,
        parsed.value,
      )
      const r = unwrap(created)
      if ("response" in r) return r.response
      return { status: 201, body: serializeGroup(r.value, input.baseUrl) }
    }
    return fail(405, `${method} is not allowed on /Groups`)
  }

  const m = /^\/Groups\/(.+)$/.exec(path)
  if (!m) return fail(404, `unknown SCIM endpoint "${path}"`)
  let id: string
  try {
    id = decodeURIComponent(m[1] as string)
  } catch {
    id = m[1] as string
  }

  switch (method) {
    case "GET": {
      const existing = await loadGroup(input, id)
      if ("response" in existing) return existing.response
      return { status: 200, body: serializeGroup(existing.group, input.baseUrl) }
    }
    case "PUT": {
      const existing = await loadGroup(input, id)
      if ("response" in existing) return existing.response
      const parsed = parseGroupWrite(input.body)
      if (!parsed.ok) {
        return fail(
          parsed.error.status,
          parsed.error.detail,
          parsed.error.scimType,
        )
      }
      const replaced = await input.directory.replaceGroup!(
        input.tenant.id,
        id,
        parsed.value,
      )
      const r = unwrap(replaced)
      if ("response" in r) return r.response
      return { status: 200, body: serializeGroup(r.value, input.baseUrl) }
    }
    case "PATCH": {
      const existing = await loadGroup(input, id)
      if ("response" in existing) return existing.response
      // Unlike a user patch, this needs no current record to resolve
      // against — membership deltas stay deltas (SCIM-AD9). The read
      // above is purely for 404 semantics.
      const normalized = normalizeGroupPatch(input.body)
      if (!normalized.ok) {
        return fail(
          normalized.error.status,
          normalized.error.detail,
          normalized.error.scimType,
        )
      }
      const patched = await input.directory.patchGroup!(
        input.tenant.id,
        id,
        normalized.value,
      )
      const r = unwrap(patched)
      if ("response" in r) return r.response
      return { status: 200, body: serializeGroup(r.value, input.baseUrl) }
    }
    case "DELETE": {
      const existing = await loadGroup(input, id)
      if ("response" in existing) return existing.response
      const deleted = await input.directory.deleteGroup!(input.tenant.id, id)
      const r = unwrap(deleted)
      if ("response" in r) return r.response
      return { status: 204, body: null }
    }
    default:
      return fail(405, `${method} is not allowed on /Groups/{id}`)
  }
}

/**
 * Handle one SCIM request end to end.
 */
export async function handleScimRequest(
  input: ScimRequestInput,
): Promise<ScimResponse> {
  const scim = input.tenant.config.scim

  const authFailure = await authenticate(scim, input.authorization)
  if (authFailure) return authFailure

  const maxPageSize = Math.min(
    scim?.maxPageSize ?? DEFAULT_PAGE_SIZE,
    PAGE_SIZE_CEILING,
  )

  const path = input.path === "" ? "/" : input.path
  const method = input.method.toUpperCase()

  // --- Discovery. GET only; these are static documents.
  if (
    path === "/ServiceProviderConfig" ||
    path === "/ResourceTypes" ||
    path === "/Schemas"
  ) {
    if (method !== "GET") {
      return fail(405, `${method} is not allowed on ${path}`)
    }
    const groups = groupsSupported(input.directory)
    const body =
      path === "/ServiceProviderConfig"
        ? serviceProviderConfig(input.baseUrl, maxPageSize)
        : path === "/ResourceTypes"
          ? resourceTypes(input.baseUrl, groups)
          : schemas(input.baseUrl, groups)
    return { status: 200, body }
  }

  // --- Users collection.
  if (path === "/Users" || path === "/Users/") {
    if (method === "GET") return listUsers(input, maxPageSize)
    if (method === "POST") return createUser(input)
    return fail(405, `${method} is not allowed on /Users`)
  }

  // --- Individual user.
  const id = userIdFrom(path)
  if (id !== null) {
    switch (method) {
      case "GET": {
        const existing = await loadUser(input, id)
        if ("response" in existing) return existing.response
        return {
          status: 200,
          body: serializeUser(existing.user, input.baseUrl),
        }
      }
      case "PUT":
        return replaceUser(input, id)
      case "PATCH":
        return patchUser(input, id)
      case "DELETE":
        // Never quietly remapped onto deactivation — see SCIM-AD8.
        return deleteUser(input, id)
      default:
        return fail(405, `${method} is not allowed on /Users/{id}`)
    }
  }

  if (path.startsWith("/Groups")) {
    return handleGroups(input, path, method, maxPageSize)
  }

  return fail(404, `unknown SCIM endpoint "${path}"`)
}

export { SUPPORTED_FILTER_HELP }
