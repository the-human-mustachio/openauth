# SCIM 2.0 — Implementation Plan

> Companion to `idp-rebuild-plan.md` and `saml-sp-plan.md`. SCIM is the
> commercial twin of SAML SP: the same enterprise buyer asks for both,
> usually in the same procurement cycle. It is **not** an auth method —
> it is a second protocol front-end alongside the OAuth/OIDC one.

## TL;DR

Accept SCIM 2.0 provisioning from corporate IdPs (Okta, Entra, and the
long tail) so customer directories stay in sync with the host's user
model — created on hire, updated on change, **deactivated on
termination**. The deprovisioning half is the one enterprises actually
audit.

**Option B (chosen 2026-09-05): the library owns the protocol, the host
owns the data.** Routing, bearer auth, RFC 7643 schema validation, PATCH
normalization, the SCIM error envelope, pagination and the discovery
documents live here; persistence happens behind a new `ScimDirectory`
port the host implements against its own tables. Nothing about the
host's user model enters the library.

Direction is **inbound**, matching SAML. The product shape stays:

```
inbound identity (SAML SP) ─┐
                            ├─→ the hub ─→ outbound OIDC
inbound directory (SCIM SP) ┘
```

## Status & Resume Point

> **Maintain this block every working session.** First thing to read
> when resuming with fresh context.

**Phase 1 COMPLETE (2026-09-05).** Users CRUD, bearer auth, filter
subset, PATCH normalization, discovery docs, error envelope and
pagination all shipped. 52 tests; conformance cases 1–14 green. Choosing
Option B settled SCIM-AD2 (the new port) implicitly; SCIM-AD3's filter
subset was implemented as proposed.

Two bugs the conformance tests caught before any IdP could:

- The `PatchOp` schema URN was compared with only one side lowercased,
  so **every** correctly-formed PATCH was rejected. Every provisioning
  update would have failed.
- The filter parser split `emails[type eq "work"].value eq "x"` on the
  *inner* `eq`, mis-reading the attribute — Entra's shape, broken.

Also removed an unused `clock` from `ScimRequestInput`: the host stamps
its own record timestamps, so the library needs no clock here.

**Phase 2 COMPLETE (2026-09-05).** Groups CRUD, membership deltas, the
group filter subset (`displayName` / `externalId` / `id`), and
`excludedAttributes=members`. Groups are **optional as a set** on the
port — a host implementing only users gets an honest 501, and discovery
advertises the Group resource type only when the host actually
implements it. Conformance case 15 green. 741 tests total.

`SCIM-AD9` was added during this phase: membership keeps the client's
intent (`addMembers` / `removeMembers`) rather than being resolved to a
final list, because resolving would make a one-member change an O(n)
read-and-rewrite on a large group.

**Recommended next action: Phase 3 — validate against a live Okta/Entra
tenant and run the Okta SCIM validator (case 16).** Everything so far is
fixture-driven; the same "no fixture substitutes for a real IdP"
argument that applies to SAML applies here, and the validator is the
stated acceptance bar. This needs real tenant credentials.

## Goals

- Pass the enterprise "SCIM / automated provisioning" procurement line
  with the same lack of asterisks SAML SP now has.
- **Certify against Okta's SCIM validator.** That is the honest finish
  line, not "the endpoints return 200".
- Keep the library boundary intact: the host owns Users, so every write
  goes through a port and no user data is persisted here.
- Absorb the protocol pedantry once — PATCH path expressions, the error
  envelope, 1-based pagination, `externalId` handling — so the host
  never re-implements RFC 7644.

## Non-Goals

- **SCIM client role.** We receive provisioning; we never push users to
  other systems. Same inbound-only posture as `SAML-AD8`, for the same
  reason: pushing outward makes us a directory vendor.
- **Storage.** The library persists no user records. Ever. See
  SCIM-AD2.
- **The full RFC 7644 filter grammar.** See SCIM-AD3.
- **Bulk operations** (`/Bulk`), **`/Me`**, **sorting**, **ETag
  versioning**. All optional in the spec; none required by Okta or
  Entra. Revisit per-deal.
- **Password sync.** SCIM can carry `password`; we will not accept it.
  Credentials belong to the auth methods, not the directory feed.
- **A console for managing SCIM connections.** Host owns the UI for
  minting the bearer token, same as every other config surface.

## Architectural Decisions

These extend the AD-series in `idp-rebuild-plan.md`, `ARCHITECTURE.md`
and `saml-sp-plan.md`.

### SCIM-AD1 — SCIM Service Provider role only, inbound

The library is the SCIM *Service Provider* (the system being
provisioned into). Corporate IdPs are the SCIM *clients*. We never
originate provisioning traffic.

This is deliberately the same shape as SAML SP and is what keeps
`SAML-AD8` coherent: identity and directory both flow inward, OIDC flows
outward. A SCIM client role would make us a provisioning hub, which is a
different product.

### SCIM-AD2 — Protocol in the library, data in the host, via a new `ScimDirectory` port

The library owns: routing, bearer authentication, RFC 7643 schema
validation, PATCH normalization, the ListResponse/Error envelopes,
pagination arithmetic, and the discovery documents. The host owns:
every byte of persistence.

**This adds a new port**, which supersedes the "no new ports" line in
`saml-sp-plan.md` § Cross-cutting Decisions. That decision was scoped to
the SAML effort (where replay state genuinely fitted `SessionStore`) and
is not a standing prohibition. Recording the supersession explicitly so
it is a decision rather than a drift.

Rationale: this is the *same* shape as everything else in the library.
`ConfigStore`, `MethodStore` and `success` are all protocol-over-
host-owned-state. SCIM is not an exception to the architecture — it is
an instance of it. This is precisely why SCIM is defensible here while
the SAML IdP role (`SAML-AD8`) was not: that one required an SSO
session the library refuses to own, whereas this one requires a port,
which is the library's normal way of not owning something.

### SCIM-AD3 — Filter support is the observed Okta/Entra subset, not RFC 7644 §3.4.2.2

`GET /Users?filter=…` is parsed into a small typed AST and handed to the
port. Supported:

```
userName eq "…"      externalId eq "…"      active eq true|false
id eq "…"            emails[type eq "work"].value eq "…"   (Entra emits this)
<expr> and <expr>    (two terms, no nesting)
```

Anything else returns `400` with `scimType: "invalidFilter"` and a
message naming what is supported.

Rationale: the full grammar has grouping, precedence, `co`/`sw`/`ew`/
`pr`/`gt`/`ge`/`lt`/`le`, complex attribute paths and nesting. Okta and
Entra emit a sliver of it — overwhelmingly `userName eq` for the
existence check before a create. Implementing the rest means either a
large parser plus a query interface the host cannot reasonably satisfy,
or silently wrong results. A narrow, honest 400 is better than both.

The AST is the port's input, never a raw string: the host must never be
handed a filter to parse itself.

### SCIM-AD4 — Bearer auth per connection, reusing the existing secret path

Each tenant's SCIM connection carries a bearer token the host mints and
gives to the IdP admin. Stored as `tokenHash` and verified with the
existing `hashClientSecret` + `timingSafeEqualStr` from
`domain/client-auth.ts` — no new crypto path, same handling as
`ClientConfig.secretHash`.

Tenant resolution uses the standard `tenantMiddleware` → host
`resolveTenant(req)` chain that `/authorize` and `/par` already use. The
token is then checked **against that tenant's** config. There is no
global token and no token→tenant lookup table in the library.

`401` on a bad token, `403` when SCIM is not enabled for the tenant —
never a 404 that leaks which tenants exist.

### SCIM-AD5 — Config lives on `TenantConfig`, not `MethodConfig`

SCIM is not an `AuthMethod`: no `/authorize`, no flow record, no
`MethodResult`, no user agent. Modelling it as one to reuse `/m/*` would
be a category error and would drag flow-cookie machinery into a
machine-to-machine API.

So: `TenantConfig.scim?: ScimConfig`, resolved by the host's existing
`ConfigStore`. Mounts at a tenant-scoped `/scim/v2/*` in
`http/router.ts` alongside `/par` and `/end_session`.

### SCIM-AD6 — PATCH is normalized in the library; the port sees a resolved delta

`PATCH /Users/:id` carries `urn:ietf:params:scim:api:messages:2.0:PatchOp`
with an `Operations` array of `{op, path?, value}`. The path grammar is
the worst part of SCIM, and Okta and Entra disagree on shapes for the
same intent (Entra sends PATCH where PUT would be natural, and both
spell "deactivate" differently).

The library resolves that into a typed delta:

```ts
{ active: false }
{ emails: [{ type: "work", value: "a@b.com", primary: true }] }
```

The port never sees `path: 'emails[type eq "work"].value'`. Absorbing
this once is the single strongest argument for the library owning SCIM
at all — it is the piece every host would otherwise get subtly wrong.

Unsupported ops return `400` / `scimType: "invalidPath"` rather than
being silently dropped, which is how provisioning drifts undetected.

### SCIM-AD7 — Users first, Groups second

Users CRUD + filter + PATCH is the whole of what most deals need on day
one. Group push is a distinct mechanism with its own membership-delta
semantics and its own Okta behaviours. Shipping Users alone is a
coherent, sellable increment; bundling Groups doubles Phase 1 and
delays the RFP answer.

### SCIM-AD8 — Deactivation and deletion are distinct port operations

Okta and Entra normally deprovision with `PATCH {active: false}`, not
`DELETE`. Some configurations do send `DELETE`. These mean materially
different things to a host — one is reversible, one may cascade — so the
port exposes them separately (`patchUser` with `active:false` vs
`deleteUser`) and the host decides its own semantics for each.

The library will not quietly map `DELETE` onto deactivation: silently
turning a destructive request into a soft one is exactly the kind of
helpfulness that loses data trails during an audit.

### SCIM-AD9 — Group membership keeps the client's intent; it is not resolved

For a user, a targeted PATCH is resolved against the current record and
the host receives the complete new value (`SCIM-AD6`). Membership is the
one place that rule is deliberately **not** applied.

The reason is size. A user's `emails` list is small and bounded;
a group's membership is neither. Resolving "add one member" against a
20,000-member group would mean reading all 20,000 rows and handing them
back on every single change — turning an O(1) insert into an O(n) read
plus rewrite, on the hottest path of a group push.

So `ScimGroupPatch` carries `addMembers` / `removeMembers`
(incremental) or `members` (full replace), and the host issues one
insert or delete. The library still normalizes the *shapes* — Okta's
`{op:"add", path:"members", value:[…]}`, Okta's
`members[value eq "u1"]` removal path, Entra's
`{op:"remove", path:"members", value:[…]}` — so no SCIM path expression
reaches the host. Only the resolution-to-a-final-list step is skipped.

The two forms are mutually exclusive: a full replace in the same request
absorbs any subsequent add/remove, so the host never receives `members`
alongside the incremental fields and needs no ordering rule of its own.

Membership operations must be idempotent on the host side — adding an
existing member or removing an absent one succeeds quietly. IdPs retry,
and a 4xx there stalls a group push indefinitely.

## Public API Surface

```ts
import type {
  ScimConfig, ScimDirectory,
  ScimUserRecord, ScimUserWrite, ScimUserPatch,
  ScimUserQuery, ScimPage,
} from "@_mustachio/openauth"
```

Root entry, not a subpath: SCIM has no Node-only dependency (it is JSON
over HTTP), so unlike SAML it stays edge-clean and available on Workers.

### Port

```ts
export type ScimDirectory = {
  getUser(t: TenantId, id: string): Promise<Result<ScimUserRecord | null>>
  findUsers(t: TenantId, q: ScimUserQuery): Promise<Result<ScimPage<ScimUserRecord>>>
  createUser(t: TenantId, u: ScimUserWrite): Promise<Result<ScimUserRecord>>
  replaceUser(t: TenantId, id: string, u: ScimUserWrite): Promise<Result<ScimUserRecord>>
  patchUser(t: TenantId, id: string, d: ScimUserPatch): Promise<Result<ScimUserRecord>>
  deleteUser(t: TenantId, id: string): Promise<Result<void>>
}
```

`ScimUserQuery` carries the parsed filter AST plus `startIndex` /
`count`. Uniqueness conflicts are signalled by the host returning a
`conflict` `AuthError`, which the library renders as `409` /
`scimType: "uniqueness"` — the host is the only party that can know.

### HTTP surface

```
GET    /scim/v2/ServiceProviderConfig     — static capability doc
GET    /scim/v2/ResourceTypes             — static
GET    /scim/v2/Schemas                   — static
GET    /scim/v2/Users                     — filter + pagination
POST   /scim/v2/Users                     — 201 + full resource
GET    /scim/v2/Users/:id
PUT    /scim/v2/Users/:id                 — full replace
PATCH  /scim/v2/Users/:id                 — normalized delta (SCIM-AD6)
DELETE /scim/v2/Users/:id
                                          — /Groups mirrors these (Phase 2)
```

Protocol details that are routine bug sources and will be asserted in
tests rather than assumed:

- `startIndex` is **1-based**, not 0.
- `ListResponse` carries `totalResults`, `startIndex`, `itemsPerPage`,
  `Resources` — with that exact capitalisation.
- Errors use `urn:ietf:params:scim:api:messages:2.0:Error` with `status`
  as a **string**.
- `meta.resourceType` / `meta.location` must be populated; Okta reads
  `location`.
- Content type is `application/scim+json`.

## Phase Plan

### Phase 1 — Users CRUD + auth + discovery ✅ (2026-09-05)

Port + config + router mount + bearer auth (SCIM-AD4), the three
discovery documents, Users CRUD, the filter subset (SCIM-AD3), PATCH
normalization (SCIM-AD6), error envelope, pagination. Memory-adapter
reference implementation of `ScimDirectory` for tests only — explicitly
not shipped as a production adapter, since real persistence is the
host's model.

### Phase 2 — Groups ✅ (2026-09-05)

Group CRUD plus membership deltas (`add`/`remove` members via PATCH),
which is where Okta's group push lands.

### Phase 3 — Certification + hardening

Okta SCIM validator run end-to-end, Entra quirk pass, rate-limit
guidance, audit events, `INTEGRATION.md` § SCIM.

## Conformance Scope

| #  | Case                                                   | Phase |
| -- | ------------------------------------------------------ | ----- |
| 1  | Bearer token accepted; wrong token → 401                | 1     |
| 2  | SCIM disabled for tenant → 403 (no tenant enumeration)  | 1     |
| 3  | `POST /Users` → 201 + full resource incl. `id`, `meta`  | 1     |
| 4  | Duplicate `userName` → 409 `scimType: "uniqueness"`     | 1     |
| 5  | `GET /Users?filter=userName eq "…"` → ListResponse      | 1     |
| 6  | Unsupported filter → 400 `invalidFilter`, names support | 1     |
| 7  | Pagination is 1-based; `itemsPerPage` honest            | 1     |
| 8  | `PATCH {active:false}` → normalized delta to the port   | 1     |
| 9  | Entra-shaped PATCH path → same normalized delta         | 1     |
| 10 | Unsupported PATCH path → 400 `invalidPath`, not dropped | 1     |
| 11 | `PUT` full replace semantics                            | 1     |
| 12 | `DELETE` reaches `deleteUser`, never deactivation       | 1     |
| 13 | `password` in payload is refused, not stored            | 1     |
| 14 | Discovery docs parse + advertise only what we serve     | 1     |
| 15 | Group create + membership add/remove                    | 2 ✅  |
| 16 | Okta SCIM validator, full run                           | 3     |
| 17 | Entra provisioning against a live tenant                | 3     |

## Risks & Mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Okta's validator is stricter than the RFC in places | Treat the validator as the acceptance bar (case 16), not the spec text. Budget a hardening pass for it. |
| Entra's PATCH shapes differ from Okta's | Normalize both to one delta (SCIM-AD6); case 9 asserts they converge. |
| Filter subset is too narrow for a real customer | 400 names what is supported, so the gap is visible immediately rather than silently wrong. Widen the subset per evidence, not per speculation. |
| Host implements the port with a race on `userName` uniqueness | Document that uniqueness is the host's invariant; the library cannot enforce what it does not store. |
| SCIM becomes a backdoor user-write API | Bearer token is per tenant and per connection; `403` when unconfigured; audit every mutation. |
| Deprovisioning silently fails and access lingers | Audit events on every mutation, and a port error surfaces as a SCIM 5xx so the IdP retries rather than marking success. |

## Open Questions

1. ~~**Filter grammar scope (SCIM-AD3)**~~ **Resolved** — shipped as the
   listed subset. Widen on evidence from a real connection.
2. ~~**New port (SCIM-AD2)**~~ **Resolved** — choosing Option B was the
   port decision; `ScimDirectory` shipped in Phase 1.
3. **Audit events.** Ride the general event set, or add
   `user_provisioned` / `user_deactivated` kinds? SAML chose to ride
   general events (`SAML-AD3`), but provisioning mutations are
   materially different from auth events and are what a compliance
   auditor will ask for. Leaning: add them.
4. **Rate limiting.** Okta can burst on initial import. The library has
   no rate-limiter port yet (it is on the Phase 8 remainder list).
   Guidance-only for now, or block on that port?
5. **`externalId` mapping.** The IdP's stable id. Certainly passed
   through to the port; open whether the library should require the host
   to index it (it is what reconciliation depends on in practice).
