---
"@_mustachio/openauth": minor
---

SCIM 2.0 group provisioning. Corporate IdPs can now push groups and their membership alongside users, covering the "group push" half of an Okta or Entra provisioning integration.

**Opt-in as a set.** Implement all six group methods on `ScimDirectory` (`getGroup`, `findGroups`, `createGroup`, `replaceGroup`, `patchGroup`, `deleteGroup`) or none. Omit them and `/scim/v2/Groups` answers `501` — and the discovery documents leave the Group resource type out entirely, so a client is never told a resource works when it does not.

**Membership keeps the client's intent rather than being resolved.** This is a deliberate departure from how user patches work, and the reason is size: a user's email list is small and bounded, a group's membership is not. Resolving "add one member" against a 20,000-member group would mean reading all 20,000 rows and writing them back on every change. So `patchGroup` receives either `addMembers` / `removeMembers` (incremental — one insert or delete) or `members` (full replace), never both. The library still normalizes the wire shapes, so no SCIM path expression reaches the host: Okta's `{op:"add", path:"members", value:[…]}`, Okta's `members[value eq "u1"]` removal path, and Entra's `{op:"remove", path:"members", value:[…]}` all converge.

**`excludedAttributes=members` is honoured.** Okta sets it while enumerating groups; `ScimGroupQuery.excludeMembers` lets the host skip loading membership rather than doing a fan-out read per group. Records come back with `members` omitted, not `[]` — an empty array would tell the client the group had been emptied.

Group filtering supports `displayName`, `externalId` and `id`. Filtering a Group by a user attribute is a `400 invalidFilter` rather than an empty list, which would read as "no such group" — a wrong answer dressed as a valid one.

Membership operations must be idempotent on the host side: adding an existing member or removing an absent one should succeed quietly, because IdPs retry and a `4xx` there stalls a group push indefinitely.
