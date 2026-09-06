---
"@_mustachio/openauth": minor
---

Close seven confirmed post-rebuild findings. Several are breaking; each is listed below with what you need to change.

**`createClient.verify()` now checks the token audience.** It passed only `issuer` to `jwtVerify`, so every relying party sharing an issuer accepted every other party's tokens — a confused deputy across the whole deployment. `aud` is now checked against the client's `clientID`. If you verify tokens minted for a **resource** (an `/authorize` call that passed `audience`), name that resource via `verify(subjects, token, { audience })`; that option was declared `@internal` and never read.

**The relying-party client is rebuilt to match the server it ships beside.** It was still the pre-rebuild client: it offered a `response_type=token` flow the IdP rejects outright, carried a legacy token shape this library never emits, and its deprecated `pkce()` method told you to use `authorize()` "which does pkce by default" — which was false.

- `authorize(redirectURI, opts?)` — the `response` positional is gone, and **PKCE is always used**. It was opt-in and off by default, so the documented server-side flow could not complete against a public client, which the IdP requires PKCE for. Persist the returned `challenge` and pass `challenge.verifier` to `exchange()`.
- `createClient` accepts `clientSecret` (and `tokenEndpointAuthMethod`, default `client_secret_basic`). `exchange()` and `refresh()` previously sent no client credentials at all, so confidential clients could not complete either flow — `refresh()` sent no `client_id` either, which the IdP refuses under RFC 6749 §6.
- Endpoints come from discovery rather than string-concatenation, so `paths` overrides are honoured.
- `VerifyResult.err` is `false` rather than `err?: undefined`, so `"err" in result` narrows. It did not before, and callers had to test truthiness.

**An invalid refresh scope no longer burns the token.** `refreshTokens` consumed the token before checking that requested scopes were a subset of the grant, so a client typo returned `invalid_scope` and then made the next legitimate refresh look like theft — enough to revoke the whole family. Validation now runs against the peeked grant, the same rule the client-authentication and DPoP gates above it already followed.

**SP-initiated SAML callbacks recover the tenant again.** The tenant middleware and the callback domain ran near-duplicate state extractors; the middleware's read only `state`, not `RelayState`, and it runs first. Every SP-initiated SAML POST therefore fell through to `resolveTenant`, breaking the documented guarantee that callbacks recover without it. There is now one shared extractor.

**`IdPOptions.subjects` is enforced.** It was required and never read: the server signed whatever `success()` returned, and the violation surfaced later in `client.verify()` — a different service, after the token was signed and written into the refresh payload. Both grants now validate first and persist the **parsed** value, which also makes `SubjectPayload`'s declared `InferOutput` type true rather than a claim about a value nothing ever parsed. A `success()` callback that does not satisfy your own schema now fails issuance with a `server_error` and an `invalid_subject_claim` audit event carrying schema paths, never values.

**`IdPOptions.hooks` is removed.** `hooks.onSuccess` / `onFailure` were accepted and never invoked. `AuditLog` already covered the same events and is the one with a consistency contract, so rather than wiring up a second observation mechanism the inert one is gone. `authorize_succeeded` — declared in the port and never emitted, while `authorize_failed` fired from six sites — is now emitted from all four paths that mint an authorization code. Its `subjectId` field is `providerSubject`: the OIDC subject is derived at `/token`, which has not run when this fires. Move any `hooks` usage to `AuditLog`.

**`registerClient` receives the credentials the framework mints.** Dynamic Client Registration generated a client id, secret, hash and a complete `ClientConfig`, passed the hook only `{ tenant, request }`, then discarded all of it — while `ARCHITECTURE.md` and the hook's own JSDoc said otherwise. The hook now receives `client` and `secret` alongside; persist `client` as-is and return it. Substituting your own id or secret still works, but substituting `secretHash` without returning the matching plaintext is refused rather than handing the relying party a credential that silently never authenticates.

Also: the test tree is type-checked in CI. `bun test` strips types without checking them and `tsconfig.test.json` covered only `test/types`, so fixtures drifted out of sync with `src` while staying green. Four such drifts are fixed, and `bun run typecheck` now covers everything.
