---
"@_mustachio/openauth": minor
---

Add `IdPOptions.onTokenIssued`, exposing the derived subject id to the host.

`TokenStore.revokeBySubject`, the exported `revokeAllForSubject`, and `onLogout`'s `revokeSubject` all take the subject id the library signs as `sub` — but nothing ever gave the host that value. It is derived privately from the claim and the receiving client's `sectorIdentifier`, and the `token_issued` audit event carries it without the claim it came from, so a host received an identifier it could not attribute to any of its own users. The revocation primitives were effectively uncallable.

That left offboarding broken. Refresh rotation never re-consults `success()` — it mints from the claim captured on the stored payload — so a deactivated user's chain keeps producing valid access tokens. A resource server the host controls can re-check its own database; any other relying party verifying against the JWKS cannot, and in a B2B deployment that is the normal case.

The hook fires for all four grants (authorization code, refresh rotation, token exchange, client credentials) with `subjectId`, the `claim` it was derived from, `clientId`, and the refresh `family`:

```ts
onTokenIssued: async ({ tenant, subjectId, claim }) => {
  await db.subjectIds.record({
    tenantId: tenant.id,
    subjectId,
    principalId: claim.properties.userId,
  })
}
```

Two things worth knowing before you build on it, both of which fail silently if assumed away:

**One principal maps to many subject ids — accumulate them, never overwrite.** Pairwise clients mix `sectorIdentifier` into the derivation (OIDC Core §8.1), so the same person has a distinct `sub` per sector; and the derivation hashes `claim.properties`, so if `success()` returns anything mutable the id changes with it and chains issued under the old one survive. Returning a single immutable id avoids the second entirely, and is what OIDC Core §2 expects of `sub`.

**A throwing hook aborts the grant**, matching `success` and `persistUpstreamTokens` rather than `AuditLog`. It runs _before_ the refresh token is persisted, so a failure leaves no chain behind — recording the mapping after the token was durable would let a hook failure produce exactly the unrevokable token this exists to prevent.

`family` is absent for `client_credentials`, which issues no refresh token and so has no chain to revoke.
