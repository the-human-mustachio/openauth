---
"@_mustachio/openauth": minor
---

SCIM 2.0 user provisioning. Corporate IdPs (Okta, Entra) can now create, update, and — most importantly — deactivate users in your system automatically, so a customer's directory stays in sync without manual steps. Inbound only: the library receives provisioning and never pushes users anywhere.

**The library owns the protocol; the host owns the data.** Routing, bearer authentication, RFC 7643 schema validation, PATCH normalization, the error envelope, pagination and the discovery documents live in the library. Every read and write goes through a new `ScimDirectory` port implemented against the host's own tables. No user records are stored in the library — it has no user model, deliberately.

**Opt-in twice.** Supply `scimDirectory` to `createIdP` (absent ⇒ `/scim/v2/*` answers 501 for the whole deployment), then enable it per tenant with `TenantConfig.scim = { enabled, tokenHash }`, where the token is hashed with the existing `hashClientSecret`.

**Endpoints:** `/scim/v2/Users` (list with filter + pagination, create) and `/scim/v2/Users/{id}` (get, replace, patch, delete), plus `ServiceProviderConfig`, `ResourceTypes` and `Schemas`. Groups are not implemented and answer 501.

**What the library absorbs so hosts don't:**

- **PATCH normalization.** Okta's pathless `{op:"replace", value:{active:false}}`, Entra's `{op:"Replace", path:"active", value:"False"}` (the boolean really does arrive as a string), and targeted paths like `emails[type eq "work"].value` all resolve to one flat delta of fully resolved values. No SCIM path expression and no merge logic reaches the host.
- **Filtering**, on a deliberately narrow subset — `userName`, `externalId`, `id`, `active`, the complex email path, and two terms joined by `and`. Anything else returns `400 invalidFilter` naming what is supported, rather than a silently wrong result. The parsed filter reaches the port as a typed tree, never a string.
- **Envelope details** that are easy to get wrong and that certification checks: string `status` in errors, capital-`R` `Resources`, 1-based `startIndex`, `application/scim+json`.

**Deliberate behaviours worth knowing:**

- `DELETE` and deactivation stay distinct. A delete is never quietly remapped to `active: false` — that would erase the distinction in an audit trail.
- `password` in a payload is refused, not silently dropped. Credentials belong to the auth methods, not the directory feed.
- A malformed PATCH operation on an attribute the library models is an error, never a silent no-op — that is how provisioning drifts undetected. An attribute it does not model is skipped instead, since there is nowhere for it to go and POST/PUT already discard it.
- A disabled or unconfigured tenant gets `403`, never `404`, so the endpoint cannot be used to probe which tenants exist.
- A port error other than `conflict` becomes a `500`, which SCIM clients retry — better than reporting success for a write that did not happen.

**`ScimDirectory` requires read-your-writes consistency**: SCIM clients confirm a create by immediately filtering for it, and a stale read there produces duplicate users. Uniqueness of `userName` is the host's to enforce (return the new `conflict` `AuthError` → `409 uniqueness`); the library cannot enforce a constraint on rows it does not store.

Also adds a `conflict` variant to `AuthError`, used by hosts to signal that a SCIM write collided with an existing record.

**Post-review corrections** (found by a branch review before release, all with regression tests): unknown attributes in a PATCH are skipped rather than rejecting the whole request — Okta pushes `title` alongside `active`, so the old behaviour took deactivation down with it, and it was asymmetric with POST/PUT which already ignore them; `/scim/v2/*` no longer distinguishes an unknown tenant from a SCIM-disabled one (the shared tenant middleware previously answered unknown tenants with an OAuth-shaped 400 before the SCIM layer ran, an enumeration oracle); a bare enterprise-extension URN used as a pathless PATCH key now resolves; `add` on a complex attribute merges sub-attributes per RFC 7644 §3.5.2.1 instead of clearing the siblings; filter structural checks ignore quoted literals, so a value containing `(` or the word `or` is no longer rejected; `count=-1` returns zero results per RFC 7644 §3.4.2.4 rather than a full page; creates carry a `Location` header per RFC 7644 §3.1; and a targeted email upsert adopts a lone untyped entry instead of appending a duplicate.

**Host error contract.** `authError.invalidRequest(…)` from a `ScimDirectory` method now becomes `400 invalidValue` rather than a generic `500`, giving the host a way to signal a *permanent* rejection. SCIM clients retry `5xx` and give up on `4xx`, so this is the difference between an IdP surfacing a problem to an admin and retrying the same doomed request forever. The motivating case is group membership naming a user the host does not have — an IdP's group push can legitimately reference a member its user push filtered out, or one deleted between operations. `conflict` still maps to `409 uniqueness`; everything else remains a retryable `500`.
