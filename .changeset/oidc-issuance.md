---
"@_mustachio/openauth": minor
---

OIDC issuance + standards extensions. Brings the library to full OIDC Core RP compatibility and rounds out the OAuth 2.1 surface deferred in 0.10.0. Third-party RPs that use OIDC client libraries (NextAuth, oidc-client-ts, AppAuth, MSAL) now work end-to-end.

**What's new:**

- **`id_token` issuance at `/token`** when the `openid` scope is granted.
- **Pairwise subject identifiers** (OIDC Core §8.1) via per-client `sectorIdentifierUri` / `subject_type: "pairwise"`.
- **OIDC `claims` request parameter** (OIDC Core §5.5) — RPs can request individual claims at the userinfo / id_token level.
- **`customScopeClaims`** — host-supplied vendor scope → claim mapping; surface non-standard scopes (e.g. `groups`, `roles`) into id_tokens without forking the library. §5.4 standard mappings always win on key collision; per-client `scopes` allowlist still gates which scopes a client may request.
- **RP-Initiated Logout** at `/end_session` (OpenID Connect RP-Initiated Logout 1.0).
- **Pushed Authorization Requests** at `/par` (RFC 9126).
- **DPoP — sender-constrained access tokens** (RFC 9449), per-client opt-in, with proof replay detection and a dedicated `dpop_replay_detected` audit event.
- **Dynamic Client Registration** at `/register` (RFC 7591), via host-supplied `registerClient` hook.
- **Discovery metadata fill-in** — every endpoint, supported algorithm, and feature flag now reflected in `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`.
- **`/introspect` enrichment** — DPoP `cnf` and OIDC claims surface where applicable.
- **Audit-log enrichment** — `token_issued` now carries `idTokenIssued` and `dpopBound` flags; new `dpop_replay_detected` event; OIDC + DPoP event surface widened so SIEM dashboards can filter by feature without parsing tokens.

**Docs:**

- New top-level [`QUICKSTART.md`](https://github.com/the-human-mustachio/openauth/blob/master/QUICKSTART.md) — 5-minute clone → install → run → verify path, with an LLM-oriented rules-that-bite section.
- `INTEGRATION.md`, `ARCHITECTURE.md`, and `ports/CONSISTENCY.md` brought up to date with the new endpoints + features.

**Non-breaking.** All additions are opt-in via scope, client config, or new optional `IdPOptions` fields. Audit event enrichment is additive (new event types + new fields on existing types).
