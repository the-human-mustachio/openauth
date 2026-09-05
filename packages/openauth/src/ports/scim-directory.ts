/**
 * `ScimDirectory` — the host's user directory, as SCIM needs to see it.
 *
 * This is the boundary from `SCIM-AD2`: the library owns the SCIM
 * protocol (routing, bearer auth, schema validation, PATCH
 * normalization, error envelope, pagination, discovery docs) and the
 * host owns every byte of persistence. The library stores no user data.
 *
 * That split is not a compromise — it is the same protocol-over-
 * host-owned-state shape as `ConfigStore`, `MethodStore` and the
 * `success` callback. The host's Users table is the host's.
 *
 * **Consistency:** read-your-writes is required. A SCIM client
 * (notably Okta) will `GET /Users?filter=userName eq "…"` immediately
 * after a `POST /Users` to confirm the create; an eventually-consistent
 * read there produces duplicate users. See `ports/CONSISTENCY.md`.
 *
 * **Errors:** return `err(authError.conflict(...))` for a uniqueness
 * violation — the library renders it as `409` with
 * `scimType: "uniqueness"`. Only the host can know about uniqueness,
 * because only the host stores the rows. Any other error becomes a
 * `500`, which SCIM clients retry; that is the correct outcome for a
 * transient failure and far better than reporting a success the host
 * did not perform.
 */
import type { Result } from "../types/result"
import type {
  ScimGroupPatch,
  ScimGroupQuery,
  ScimGroupRecord,
  ScimGroupWrite,
  ScimPage,
  ScimUserPatch,
  ScimUserQuery,
  ScimUserRecord,
  ScimUserWrite,
} from "../types/scim"
import type { TenantId } from "../types/tenant"

export type ScimDirectory = {
  /** `null` (not an error) when no user has that id in this tenant. */
  getUser(
    tenantId: TenantId,
    id: string,
  ): Promise<Result<ScimUserRecord | null>>

  /**
   * Query users. `query.startIndex` is 1-based and `query.count` is
   * already clamped; `query.totalResults` in the response must be the
   * full match count, not the page length.
   */
  findUsers(
    tenantId: TenantId,
    query: ScimUserQuery,
  ): Promise<Result<ScimPage<ScimUserRecord>>>

  /**
   * Create a user. Return `conflict` if `userName` (or another
   * uniqueness constraint of yours) is already taken — the library
   * cannot check that for you.
   */
  createUser(
    tenantId: TenantId,
    user: ScimUserWrite,
  ): Promise<Result<ScimUserRecord>>

  /**
   * Full replace (`PUT`). Attributes absent from `user` are cleared, per
   * RFC 7644 §3.5.1 — this is a replace, not a merge. Use `patchUser`
   * for partial updates.
   */
  replaceUser(
    tenantId: TenantId,
    id: string,
    user: ScimUserWrite,
  ): Promise<Result<ScimUserRecord>>

  /**
   * Apply a normalized delta. Present key ⇒ set; absent ⇒ leave alone;
   * `null` ⇒ clear. The library has already resolved SCIM path
   * expressions, so no parsing is needed here.
   *
   * `{ active: false }` is the ordinary deprovisioning signal and is
   * usually the single most important operation to implement correctly.
   */
  patchUser(
    tenantId: TenantId,
    id: string,
    patch: ScimUserPatch,
  ): Promise<Result<ScimUserRecord>>

  /**
   * Hard delete (`DELETE`). Distinct from deactivation on purpose
   * (`SCIM-AD8`): the library will not quietly turn a destructive
   * request into a soft one. Hosts that do not want cascading deletes
   * should implement this as a tombstone and say so in their runbook —
   * but that decision is theirs to make explicitly, not the library's to
   * make silently.
   */
  deleteUser(tenantId: TenantId, id: string): Promise<Result<void>>

  // ─── Groups ───
  //
  // Optional as a set: a host that only needs user provisioning can omit
  // all six, and `/scim/v2/Groups` then answers 501 instead of failing
  // at runtime. Implement all of them or none — a half-implemented
  // Groups surface fails an IdP's group push in confusing ways.

  getGroup?(
    tenantId: TenantId,
    id: string,
  ): Promise<Result<ScimGroupRecord | null>>

  /**
   * `query.excludeMembers` is set when the client asked for
   * `excludedAttributes=members`. Honour it by not loading membership —
   * Okta sets it while enumerating groups, and ignoring it turns a cheap
   * listing into a fan-out read per group.
   */
  findGroups?(
    tenantId: TenantId,
    query: ScimGroupQuery,
  ): Promise<Result<ScimPage<ScimGroupRecord>>>

  createGroup?(
    tenantId: TenantId,
    group: ScimGroupWrite,
  ): Promise<Result<ScimGroupRecord>>

  /** Full replace, including membership. */
  replaceGroup?(
    tenantId: TenantId,
    id: string,
    group: ScimGroupWrite,
  ): Promise<Result<ScimGroupRecord>>

  /**
   * Apply a normalized group delta.
   *
   * Exactly one membership shape arrives at a time: `members` (replace
   * everything) or `addMembers` / `removeMembers` (incremental). The
   * incremental form exists so a 20,000-member group does not have to be
   * read and rewritten to add one person — see `SCIM-AD9`. Adding an
   * existing member or removing an absent one must succeed quietly;
   * IdPs retry and expect idempotence.
   */
  patchGroup?(
    tenantId: TenantId,
    id: string,
    patch: ScimGroupPatch,
  ): Promise<Result<ScimGroupRecord>>

  deleteGroup?(tenantId: TenantId, id: string): Promise<Result<void>>
}
