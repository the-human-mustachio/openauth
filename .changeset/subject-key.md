---
"@_mustachio/openauth": patch
---

Add `IdPOptions.subjectKey`, so `sub` can be derived from an identifier the host controls.

By default the subject id is a hash of the whole of `claim.properties`, which is stable only if that record is. It usually is not — and the library is what makes it so: `customScopeClaims` publishes id_token and `/userinfo` claims from that same record ("sourced from `SubjectClaim.properties`"), so exposing a role or a display name is precisely what `properties` is for. Do that, and `sub` moves whenever the published value moves, contrary to OIDC Core §2, which requires it never be reassigned. The two designs pulled against each other; this reconciles them without stripping `properties` back and breaking every customer reading those claims.

```ts
subjectKey: (claim) => (claim.properties as { userId: string }).userId
```

The library keeps the derivation. Your key is hashed, so an internal id never reaches a relying party, and the receiving client's `sectorIdentifier` is still mixed in, so pairwise subjects (OIDC Core §8.1) are unchanged. `claim.type` still participates too — keep it stable for a given identity, or `sub` forks the same way mutable properties made it fork.

An empty or blank key fails issuance rather than being hashed: an empty seed would give every subject of that type the same `sub`, which is silent cross-user token confusion. A throwing hook fails issuance too.

Additive and opt-in — nothing changes for a deployment that does not set it. **Adopting it reassigns `sub` once**: derivation runs on every mint, so existing refresh chains emit the new id at their next rotation. Revoke outstanding chains at cutover, or accept a window in which both ids are live; the `onTokenIssued` map added in 0.15.0 accumulates ids precisely so both stay revocable. For a host whose `properties` were never stable there is nothing to break — the id was already moving.
