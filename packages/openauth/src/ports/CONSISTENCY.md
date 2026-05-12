# Port consistency contracts

This document is **normative**. Adapter implementations that do not meet
the per-method consistency requirement below are **not certified for
production** and must not be wired into a deployed IdP. The phase-1 test
fixtures and the phase-6 adapter integration suite exist to verify these
contracts hold against real backends.

Storage ports differ in their consistency needs because the security
properties of the OAuth flows depend on specific atomicity / linearizability
guarantees at specific points. A blanket "use a strongly consistent KV"
overspecifies adapters that don't need that on the read-eventual paths
(tenant config, JWKS); under-specifying any of the strong paths
(`consumeCode`, `consumeRefresh`, `consumeFlow`) is a critical security bug.

## Per-method consistency contracts

| Port           | Method                                                              | Required                                                                                                               | Why                                                                                                                                                                                                                                                                  |
| -------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TokenStore`   | `saveCode(code, payload, ttl)`                                      | **Strong, atomic.** Payload **encrypted at rest** with a key from `KeyStore`; `ttl ≤ 60 s` (framework refuses larger). | Code must be created exactly once and visible to the next `consumeCode` on any node. Payload may carry upstream tokens — see _Code payload confidentiality_ in plan.                                                                                                 |
| `TokenStore`   | `consumeCode(code)`                                                 | **Strong, CAS.** Returns the **decrypted** payload on success.                                                         | Single-use; second consumption must fail deterministically. Race with itself must resolve to one winner.                                                                                                                                                             |
| `TokenStore`   | `saveRefresh(refresh, payload)`                                     | **Strong, atomic.**                                                                                                    | New refresh tokens issued during rotation must be immediately retrievable on the next request.                                                                                                                                                                       |
| `TokenStore`   | `consumeRefresh(refresh, options)`                                  | **Strong, CAS with reuse-detection window** (default 60 s).                                                            | Core of refresh-token rotation security. Concurrent presentations resolve to one winner; reuse within the window triggers the revoke chain.                                                                                                                          |
| `TokenStore`   | `peekRefresh(refresh)`                                              | **Eventual acceptable.** Non-destructive read; must never mark the token consumed.                                     | Used by `/revoke` for token-to-client binding (RFC 7009 §2.2) and by the refresh-grant for client auth + audit fields. Race losers fall through to `consumeRefresh`, which is the strong gate, so a stale peek can only delay — not bypass — single-use enforcement. |
| `TokenStore`   | `revokeFamily(family)`                                              | Strong preferred; eventual acceptable with documented SLA.                                                             | Reuse-detection must invalidate the whole chain. Brief lag is tolerable.                                                                                                                                                                                             |
| `TokenStore`   | `revokeBySubject(tenant, subject)`                                  | Strong preferred; eventual acceptable with documented SLA.                                                             | Revocation must propagate quickly. A few seconds of lag is tolerable.                                                                                                                                                                                                |
| `SessionStore` | `saveFlow(flowId, payload, ttl)`                                    | **Strong, atomic.** `ttl == expiresAt - createdAt`.                                                                    | Flow record must be visible on the callback request to `consumeFlow`.                                                                                                                                                                                                |
| `SessionStore` | `updateFlowMethodState(flowId, state)`                              | **Strong, atomic.** Resolves **before** the user-agent redirect is sent.                                               | Upstream PKCE verifier / nonce must be durably persisted before the redirect, otherwise the callback cannot validate.                                                                                                                                                |
| `SessionStore` | `consumeFlow(flowId)`                                               | **Strong, atomic delete-on-read** that **returns the full `FlowRecord`** (`CAS` or `DELETE … RETURNING`).              | Single-use; concurrent consumption resolves to one winner. The record is returned so the framework can snapshot fields into the auth-code payload before disposal.                                                                                                   |
| `SessionStore` | `createSession / readSession / revokeSession` (optional long-lived) | **Strong.**                                                                                                            | Session creation must be immediately readable on the next request.                                                                                                                                                                                                   |
| `KeyStore`     | `currentSigningKey()` / `currentEncryptionKey()`                    | Strong.                                                                                                                | Active key must be unambiguous.                                                                                                                                                                                                                                      |
| `KeyStore`     | `signingKeys()` (JWKS)                                              | Eventual OK (with TTL).                                                                                                | Verifiers tolerate brief JWKS lag during rotation.                                                                                                                                                                                                                   |
| `KeyStore`     | `getEncryptionKey(kid)`                                             | Strong.                                                                                                                | Required to decrypt code payloads encrypted under non-current keys during the overlap window.                                                                                                                                                                        |
| `ConfigStore`  | `getTenantConfig(id)`                                               | **Eventual + bounded staleness (TTL ≤ 60 s).** Invalidation hook fires on update.                                      | Read-heavy, write-rare. Aggressive caching is desirable.                                                                                                                                                                                                             |
| `ConfigStore`  | `putTenantConfig(config)`                                           | **Strong write + immediate invalidation** of cached entries for the affected `TenantId`.                               | Subsequent `getTenantConfig` must reflect the new value once the write resolves.                                                                                                                                                                                     |
| `MethodStore`  | `getMethodConfig` / `listMethods`                                   | Same as `ConfigStore.getTenantConfig`.                                                                                 | Subset of tenant config.                                                                                                                                                                                                                                             |
| `MethodStore`  | `putMethodConfig` / `deleteMethodConfig`                            | Strong write + immediate invalidation.                                                                                 | Console-driven mutations must take effect on the next request.                                                                                                                                                                                                       |
| `AuditLog`     | `log(event)`                                                        | Append-only, durable. Cross-instance ordering **not** required (consumers sort by `timestamp` + `actor`).              | Loss = audit gap; ordering is a UI / SIEM concern.                                                                                                                                                                                                                   |

## Implications for adapter choice

| Backend                        | Acceptable for                                                                                                                            | NOT acceptable for                                                                                                                                                |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cloudflare KV**              | `ConfigStore`, `MethodStore`, `KeyStore.signingKeys()` (read cache), `AuditLog` (with buffered writes).                                   | `TokenStore.saveCode` / `consumeCode` / `saveRefresh` / `consumeRefresh`, `SessionStore.saveFlow` / `consumeFlow`. Eventual consistency violates these contracts. |
| **Cloudflare D1**              | Everything, **provided** token / code / flow operations use the **D1 Sessions API with bookmarks** (or primary-pinned reads) per AD8.     | Token / code / flow operations against non-pinned read replicas without bookmarks.                                                                                |
| **Cloudflare Durable Objects** | `SessionStore` (flow records) and `TokenStore` (deployments without D1).                                                                  | —                                                                                                                                                                 |
| **AWS DynamoDB**               | Everything, **provided** strong-consistency / conditional-write semantics are used (`ConsistentRead=true`, `ConditionExpression` on CAS). | Default eventual-consistency reads on token / code / flow operations.                                                                                             |
| **Postgres**                   | Everything (row-level locking / `SELECT … FOR UPDATE` on the refresh path; `DELETE … RETURNING` on consume paths).                        | —                                                                                                                                                                 |
| **In-memory**                  | Tests + single-instance dev. Trivially satisfies all contracts (single process).                                                          | Multi-instance production.                                                                                                                                        |

### D1 read-replication caveat

D1 supports asynchronous read replication. All token / code / flow methods
above (the security-critical paths) **must** use the D1 Sessions API with
bookmarks, or primary-pinned reads, to guarantee read-after-write
consistency. The D1 adapter is certified only when its integration tests
demonstrate, under simulated replication lag:

1. `consumeCode` / `consumeFlow` immediately after the matching `saveCode` /
   `saveFlow` return the row.
2. `consumeRefresh` CAS resolves to exactly one winner under concurrent
   attempts on the same token.
3. `revokeBySubject` propagates within the documented SLA.

Read-eventual paths (`ConfigStore.getTenantConfig`, JWKS) may use replicas
freely.

Source: <https://developers.cloudflare.com/d1/best-practices/read-replication/>.

## Test fixtures

Phase 2 provides parameterized port-conformance tests
(`packages/openauth/test/ports/`) that run against any adapter. An adapter
that fails any test in that suite is not certified. Phase 6 adapters must
pass the full suite against a real (or close-to-real) backend.

The fixture set covers, at minimum:

- Single-use atomicity of `consumeCode`, `consumeRefresh`, `consumeFlow`
  under concurrent presentations.
- TTL enforcement (`saveCode` with `ttl > 60` rejected).
- Encryption-at-rest verification (`consumeCode` returns plaintext only after
  decryption — direct DB inspection shows ciphertext).
- Refresh reuse detection within the window.
- `revokeFamily` and `revokeBySubject` propagation.
- `ConfigStore` invalidation hook fires within bounded staleness.
- JWKS overlap window — keys retired during the verification window remain
  in `signingKeys()` until removed.
