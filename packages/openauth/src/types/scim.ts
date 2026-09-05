/**
 * SCIM 2.0 — public types.
 *
 * The library is the SCIM **Service Provider** (the system being
 * provisioned into); corporate IdPs are the SCIM clients. Inbound only —
 * we never originate provisioning traffic. See `SCIM-AD1` in
 * `docs/plans/claude/scim-plan.md`.
 *
 * These types are the whole contract between the library's protocol
 * layer and the host's data layer. No SCIM JSON shape, path expression,
 * or filter string reaches the host: it receives validated, normalized
 * values and returns records. See `SCIM-AD2`.
 *
 * Plain TypeScript, no third-party types, no Node APIs — SCIM is JSON
 * over HTTP, so unlike SAML this surface lives on the root entry and
 * stays edge-clean.
 */

/** RFC 7643 §4.1.2 — a multi-valued attribute entry. */
export type ScimMultiValue = {
  value: string
  /** e.g. `"work"` / `"home"` / `"mobile"`. */
  type?: string
  /** At most one entry per attribute should be primary. */
  primary?: boolean
}

/** RFC 7643 §4.1.1 — the `name` complex attribute. */
export type ScimName = {
  formatted?: string
  familyName?: string
  givenName?: string
  middleName?: string
  honorificPrefix?: string
  honorificSuffix?: string
}

/**
 * RFC 7643 §4.3 — the enterprise user extension
 * (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`).
 * Okta and Entra both populate parts of this; `department` and
 * `manager` are the ones hosts usually care about.
 */
export type ScimEnterpriseUser = {
  employeeNumber?: string
  costCenter?: string
  organization?: string
  division?: string
  department?: string
  /** `manager.value` is the manager's SCIM `id`. */
  manager?: { value?: string; displayName?: string }
}

/**
 * A user as the **host** stores it. Returned from every `ScimDirectory`
 * read and write.
 *
 * `id` is the host's stable identifier and becomes the SCIM resource id
 * in URLs — it must be opaque, stable, and URL-safe.
 *
 * `externalId` is the **IdP's** identifier for the same person. It is
 * what reconciliation depends on in practice (a user can change
 * `userName`; `externalId` survives), so hosts should persist and index
 * it even though SCIM marks it optional.
 */
export type ScimUserRecord = {
  id: string
  externalId?: string
  userName: string
  /** `false` is the normal deprovisioning signal — see `SCIM-AD8`. */
  active: boolean
  name?: ScimName
  displayName?: string
  emails?: ScimMultiValue[]
  phoneNumbers?: ScimMultiValue[]
  enterprise?: ScimEnterpriseUser
  /** Unix ms. Surfaced as `meta.created` when present. */
  createdAt?: number
  /** Unix ms. Surfaced as `meta.lastModified` when present. */
  updatedAt?: number
}

/**
 * A validated create / replace payload. Same shape as a record minus
 * the host-assigned `id` and timestamps.
 *
 * `active` is always present: SCIM defaults it to `true` on create, and
 * resolving that default in the library rather than the host keeps the
 * semantics in one place.
 *
 * Note there is no `password` field, deliberately — see `SCIM-AD1`
 * non-goals. A `password` in the payload is refused, not silently
 * dropped.
 */
export type ScimUserWrite = {
  externalId?: string
  userName: string
  active: boolean
  name?: ScimName
  displayName?: string
  emails?: ScimMultiValue[]
  phoneNumbers?: ScimMultiValue[]
  enterprise?: ScimEnterpriseUser
}

/**
 * A **normalized** PATCH delta (`SCIM-AD6`).
 *
 * The library resolves `urn:ietf:params:scim:api:messages:2.0:PatchOp`
 * operations — including path expressions like
 * `emails[type eq "work"].value` and the different shapes Okta and Entra
 * emit for the same intent — into this flat delta. The host never parses
 * a SCIM path.
 *
 * Present key ⇒ set to that value. Absent key ⇒ leave untouched.
 * `null` ⇒ the attribute was removed and should be cleared.
 */
export type ScimUserPatch = {
  externalId?: string | null
  userName?: string
  active?: boolean
  name?: ScimName | null
  displayName?: string | null
  emails?: ScimMultiValue[] | null
  phoneNumbers?: ScimMultiValue[] | null
  enterprise?: ScimEnterpriseUser | null
}

/**
 * Attributes the filter subset may reference (`SCIM-AD3`).
 *
 * `emails.value` is the normalized form of the complex path Entra emits
 * (`emails[type eq "work"].value`) — the host matches on any email
 * value and need not model the `type` qualifier.
 */
export type ScimFilterAttribute =
  | "id"
  | "userName"
  | "externalId"
  | "active"
  | "emails.value"

/**
 * The parsed filter, as a small typed tree. The host never receives the
 * raw filter string — parsing is the library's job, and an expression
 * outside the supported subset is rejected with `400 invalidFilter`
 * before the port is called.
 */
export type ScimFilter =
  | { op: "eq"; attribute: ScimFilterAttribute; value: string | boolean }
  | { op: "and"; left: ScimFilter; right: ScimFilter }

/** Input to `ScimDirectory.findUsers`. */
export type ScimUserQuery = {
  /** Absent ⇒ unfiltered list. */
  filter?: ScimFilter
  /**
   * **1-based**, per RFC 7644 §3.4.2.4 — not zero. Already clamped to
   * `>= 1` by the library.
   */
  startIndex: number
  /** Page size, already clamped to the connection's configured maximum. */
  count: number
}

/**
 * One page of results. `totalResults` is the count of everything
 * matching the filter, not the size of `resources` — SCIM clients use it
 * to drive pagination, so a host that returns the page size here will
 * make Okta loop or stop early.
 */
export type ScimPage<T> = {
  resources: T[]
  totalResults: number
}

/**
 * Per-tenant SCIM connection config, carried on `TenantConfig.scim`.
 *
 * SCIM is not an `AuthMethod` — no `/authorize`, no flow, no user agent
 * — so it is tenant-level config rather than a `MethodConfig`
 * (`SCIM-AD5`).
 */
export type ScimConfig = {
  /** `false` (or absent config) ⇒ `/scim/v2/*` responds 403 for this tenant. */
  enabled: boolean
  /**
   * Hash of the bearer token issued to the IdP, produced with
   * `hashClientSecret` — the same treatment as
   * `ClientConfig.secretHash`. Never store the raw token.
   */
  tokenHash: string
  /**
   * Largest page this connection will return, whatever the client asks
   * for. Defaults to 100; hard-capped at 500 so a hostile or
   * misconfigured `count` cannot ask the host for an unbounded read.
   */
  maxPageSize?: number
}
