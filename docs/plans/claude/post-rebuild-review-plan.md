# Post-Rebuild Review — Action Plan

**Status:** open
**Source:** three-angle review (security / bugs / architecture) of the
rebuild-idp branch, May 2026. Every finding below was spot-checked
against the actual code at the cited file:line before being captured
here. Severity reflects post-verification adjustment, not the raw agent
output.

**How to use this plan**

- Pick items in tier order (Critical → High → Medium → Low). Inside a
  tier, work shortest first unless there's a dependency.
- Update the checkbox in **Progress** when an item lands. Add the commit
  SHA next to it for traceability.
- The status header at the top tracks totals.
- Effort estimates: **S** = under an hour, **M** = a few hours, **L** =
  a day or more.

## Progress

| Tier | Open | Done | Total |
|---|---|---|---|
| Critical | 0 | 2 | 2 |
| High | 9 | 3 | 12 |
| Medium | 11 | 0 | 11 |
| Low | 6 | 0 | 6 |
| **Total** | **26** | **5** | **31** |

---

## Critical — ship-blockers

### C1 — Wrap JWT signing keys at rest in Postgres + Dynamo `KeyStore` adapters

- [x] **Status:** done
- **Severity:** Critical · **Effort:** L
- **Files:** `packages/openauth/src/adapters/postgres/key-store.ts:118-122`, `packages/openauth/src/adapters/dynamo/key-store.ts:114-116`
- **Problem:** `exportJWK(privateKey)` is `JSON.stringify`'d straight into the `private_jwk` column / DynamoDB attribute. A read-only DB compromise (SQL injection elsewhere, leaked backup, replica access, snapshot exfil) yields full token-forging power for every tenant. The KMS adapter wraps correctly; Postgres + Dynamo don't.
- **Fix:** Either (a) require an encryption-key source on construction and self-wrap with `KeyStore.currentEncryptionKey`, or (b) accept a `wrap(plain)/unwrap(ct)` callback. Ship a migration that re-wraps existing rows. At minimum, document in `INTEGRATION.md` §4 that production Postgres / Dynamo deployments MUST pair with `KmsKeyStore` for signing keys. The current docs imply the adapter is production-ready.
- **Verification note:** Confirmed at code. KMS adapter shows the correct pattern.

### C2 — Add `attribute_exists(pk)` guard to DynamoDB `updateFlowMethodState`

- [x] **Status:** done
- **Severity:** Critical · **Effort:** M
- **Files:** `packages/openauth/src/adapters/dynamo/session-store.ts:83-106` (the code itself comments the race at lines 96-102)
- **Problem:** The `put` is unconditional. If `consumeFlow` runs between the `get` and `put`, the deleted row is recreated; the original caller can re-consume and bypass flow-reuse detection. The comment claims "framework ordering" makes it safe — but the framework has no such ordering contract.
- **Fix:** Extend `DynamoExecutor.put` to accept `ConditionExpression: attribute_exists(pk)`. Surface a typed failure (`unknown_state`) when the condition fails.
- **Verification note:** Confirmed. The race is acknowledged in the source.

---

## High — real bugs / vulnerabilities

### H1 — Pin `algorithms` on every `jwtVerify` call

- [x] **Status:** done
- **Severity:** High · **Effort:** S
- **Files:** `packages/openauth/src/domain/jwt.ts:44-61`, `packages/openauth/src/domain/token-exchange.ts:99-101`, `packages/openauth/src/domain/introspect.ts:75-77`
- **Problem:** `jwtVerify` is called without `algorithms: [...]`. The kid-resolver imports the key with its declared alg, and `jose` rejects header/key alg mismatch — so pure alg confusion is mitigated **today**. But the next person who lands an HS-capable key in the store (test fixtures, ops error, or via C1 escalation) opens a confusion path. Defense in depth.
- **Fix:** Pass `{ algorithms: ["ES256", "EdDSA"] }` (or derive from the loaded `SigningKey.alg` set, excluding any `HS*`/`none`) to every `jwtVerify` call. Explicitly reject `alg: "none"` at parse.
- **Verification note:** Confirmed.

### H2 — Delete orphan top-level `src/pkce.ts` validator + `plain` branch

- [x] **Status:** done
- **Severity:** High · **Effort:** S
- **Files:** `packages/openauth/src/pkce.ts:9,32-40`
- **Problem:** `validatePKCE` accepts `method: "S256" | "plain"` and compares with `===` (line 39, with `// timing safe equals?` comment showing the author knew). It's dead code in `src/` — IdP-side validation lives in `domain/pkce.ts`. Reachable via deep import (`@_mustachio/openauth/pkce`), so a careless internal refactor or an ill-advised consumer could pick it up.
- **Fix:** Delete `validatePKCE` and the `"plain"` branch. Keep `generatePKCE` (used by `client.ts`) and harden it to S256-only.
- **Verification note:** Confirmed not re-exported from `src/index.ts`. Reachable via `@_mustachio/openauth/pkce` deep import only.

### H3 — Wrong-client `/revoke` returns `invalid_grant`, leaks token existence

- [x] **Status:** done
- **Severity:** High · **Effort:** S
- **Files:** `packages/openauth/src/domain/revoke.ts:93-101`
- **Problem:** Confidential client A presenting a valid token belonging to client B gets `400 invalid_grant`; a successful own-token revoke or an unknown token gets 200. Existence oracle. INTEGRATION.md §13 documents this as intentional — it's wrong. RFC 7009 §2.2 wants a silent no-op.
- **Fix:** Treat wrong-client revoke as a successful no-op (200, empty body). Audit internally as a wrong-client attempt.
- **Verification note:** Confirmed. Branch returns `invalid_grant` at line 94-98.

### H4 — Authenticate client *before* the client-mismatch check on refresh-grant

- [ ] **Status:** not started
- **Severity:** High · **Effort:** S
- **Files:** `packages/openauth/src/domain/refresh.ts:74-87`
- **Problem:** Mismatch check at line 74 returns `invalid_grant` ("does not belong to this client") before `verifyClientCredentials` at line 86. An attacker with a stolen refresh token can probe candidate `client_id`s without burning the token. Unifies as an oracle distinct from `invalid_client`.
- **Fix:** Verify client credentials (existence + secret) first. Unify mismatch + auth failure as `invalid_grant` with identical wording.
- **Verification note:** Confirmed at code.

### H5 — Add a tenant-resolution path that works for `client_credentials`

- [ ] **Status:** not started
- **Severity:** High · **Effort:** M
- **Files:** `packages/openauth/src/http/handlers/token.ts:96-101` → `packages/openauth/src/domain/client-credentials.ts:65`
- **Problem:** `POST /token` with `grant_type=client_credentials` calls `deps.resolveTenant(c.req.raw)` against a raw `Request` whose body hasn't been parsed onto the URL. INTEGRATION.md §5.1 / §7 tells hosts to read `client_id` from the URL query string, which doesn't exist for m2m (it's in the form body or Basic-auth header). Hosts following the documented pattern fail tenant resolution for every m2m token request.
- **Fix:** After parsing the body, synthesize a URL with `client_id` injected as a query param before calling `resolveTenant`, OR expose a separate `resolveTenantForClient(clientId)` hook on `IdPOptions`. Add an integration test covering m2m on a host whose resolver depends on `client_id`. Update INTEGRATION.md §5.1.
- **Verification note:** Confirmed at code.

### H6 — Authenticate against presenting client's tenant *before* loading the token's tenant in `/introspect`

- [ ] **Status:** not started
- **Severity:** High · **Effort:** S
- **Files:** `packages/openauth/src/domain/introspect.ts:82-93`
- **Problem:** Current order: (1) verify JWT → if unverifiable return `{active: false}`; (2) `getTenantConfig(claims.tid)`; (3) find client by `req.clientId` in *that* tenant → if absent `invalid_client`; (4) verify creds. A caller presenting a valid foreign token + their own valid creds in a different tenant gets a distinguishable `invalid_client` response — confirms whether their client exists in the foreign token's tenant. Narrower than the agent framed, but still a leak.
- **Fix:** Authenticate against the **presenting client's tenant** (e.g., via a separate tenant resolution from the request) first. Only then attempt to verify the token. If the presenter's tenant ≠ token's tenant, return `{active: false}`.
- **Verification note:** Confirmed. Severity reduced from agent's framing because weaponization requires already possessing a valid foreign token.

### H7 — Auto-invalidate `MethodCache` on tenant-config changes

- [ ] **Status:** not started
- **Severity:** High · **Effort:** M
- **Files:** `packages/openauth/src/domain/method-cache.ts:92-105`, `packages/openauth/src/index.ts` (wire site), `packages/openauth/src/ports/config-store.ts` (hook contract)
- **Problem:** `MethodCache.invalidate(tenantId, methodId?)` exists, but **nothing** calls it. `buildOauth2Method` / `buildOidcMethod` capture `clientSecret` in closures. A tenant that rotates its upstream client secret with Google / Okta / etc. continues to authenticate with the old secret indefinitely.
- **Fix:** Wire `ConfigStore.onTenantConfigChanged` (or a parallel `onMethodConfigChanged`) to `MethodCache.invalidate`. Alternative: key the cache by `(tenantId, methodId, hash(config))` so config mutations bust the entry naturally. Add a test that rotates a method's config and asserts the next request picks up the new value.
- **Verification note:** Confirmed by grep — zero callers of `methodCache.invalidate` in `src/`.

### H8 — Rename shadowed `ok` binding in `exchangeCode`

- [ ] **Status:** not started
- **Severity:** High · **Effort:** S
- **Files:** `packages/openauth/src/domain/token.ts:112`
- **Problem:** `const ok = await validatePkce(…)` shadows the `ok` constructor imported at the top of the file. No broken caller today; the very next branch added after line 118 that returns `ok(...)` will type-error or (worse, with `as never`) misbehave at runtime.
- **Fix:** Rename to `pkceValid`.
- **Verification note:** Confirmed at code.

### H9 — Stop passing `"unknown"` strings as `TenantId` to the audit log

- [ ] **Status:** not started
- **Severity:** High · **Effort:** M (overlaps with H10)
- **Files:** `packages/openauth/src/domain/refresh.ts:93-101, 162-172`
- **Problem:** `parseReuseSignal` returns `{ tenantId: "unknown" }` when the adapter's description doesn't match the regex. The audit call casts via `as never`. Downstream `AuditLog.log` implementations will fail on a `NOT NULL` / FK constraint when written against Postgres / Dynamo audit-log tables.
- **Fix:** Use the **peeked payload's `tenantId`** as the ground truth (already loaded and properly branded at `refresh.ts:60`). Only fall back to the parsed signal for `family`. Drop `as never`. Replace the parsed `tenantId`/`subjectId` fields with `peekedPayload.tenantId` / `peekedPayload.subjectId`.
- **Verification note:** Confirmed.

### H10 — Replace the regex-parsed reuse signal with a typed `AuthError` field

- [ ] **Status:** not started
- **Severity:** High · **Effort:** L
- **Files:** `packages/openauth/src/domain/refresh.ts:93-101, 162-172`; `packages/openauth/src/adapters/memory/token-store.ts`, `…/postgres/token-store.ts`, `…/dynamo/token-store.ts` (each adapter writes the magic string); `packages/openauth/src/types/error.ts` (extend variant); `packages/openauth/src/ports/token-store.ts` (port doc); `packages/openauth/test/ports/token-store.ts` (conformance assertion).
- **Problem:** Adapters smuggle reuse-detection signals through `AuthError.description` ("…(family=…,tenant=…,subject=…)"). Any 4th-party adapter that returns a perfectly valid `invalid_grant` with different phrasing silently degrades audit fidelity. The port-conformance suite never asserts the format.
- **Fix:** Extend `AuthError` (or the `invalid_grant` variant) with an optional `reuseSignal?: { family, tenantId, subjectId }`. Populate it from every adapter. Assert presence in `test/ports/token-store.ts`. Drop the regex.
- **Verification note:** Confirmed across all three production adapters.

### H11 — Don't issue refresh tokens on `client_credentials`

- [ ] **Status:** not started
- **Severity:** High · **Effort:** M
- **Files:** `packages/openauth/src/domain/client-credentials.ts:159-174`; `packages/openauth/src/domain/token.ts` (`mintTokens` signature)
- **Problem:** `mintTokens` is called, which durably saves a refresh token via `tokenStore.saveRefresh`, then the response strips it (`{ refresh_token: _drop, ...rest }`). Per RFC 6749 §4.4.3 a client_credentials grant SHOULD NOT issue a refresh token. The orphaned token sits in the DB until its TTL expires.
- **Fix:** Add `skipRefresh?: boolean` to `mintTokens` args, or extract a separate `mintAccessOnly` helper. The orphaned-row issue is fixed naturally.
- **Verification note:** Confirmed.

### H12 — Decide what `TenantContext.request.custom` is

- [ ] **Status:** not started
- **Severity:** High · **Effort:** M
- **Files:** `packages/openauth/src/types/tenant.ts:172-180`; `packages/openauth/src/http/middleware/tenant.ts:146`; `packages/openauth/src/domain/{callback.ts:74,155,refresh.ts:124,token.ts:125,token-exchange.ts,client-credentials.ts:141}`
- **Problem:** `TenantContext.request.custom: Record<string, unknown>` is documented as "whatever the user attached during `resolveTenant`." `IdPOptions.resolveTenant` returns `Promise<Result<TenantId>>` — no slot for a custom blob. Every code path hardcodes `custom: {}`. `domain/callback.ts:74,155` has a `buildCustomContext` hook, but it's not wired through `HttpDeps` or `IdPOptions`.
- **Fix:** Either (a) widen `resolveTenant` to return `Promise<Result<{ tenantId, custom? }>>` and thread it through; OR (b) expose `IdPOptions.buildCustomContext(req): Record<string, unknown>` as a first-class hook and wire it; OR (c) drop `custom` from `TenantContext` entirely. Pick one — the current state is an unimplementable public contract.
- **Verification note:** Confirmed. Only `domain/callback.ts:155` actually uses the hook, and only internally.

---

## Medium — design / maintainability

### M1 — Encrypt code payloads at the domain boundary, not in each adapter

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** L
- **Files:** `packages/openauth/src/adapters/memory/token-store.ts:3261,3284`; `…/postgres/token-store.ts:3441,3485`; `…/dynamo/token-store.ts:3723,3767`; `packages/openauth/src/domain/token.ts:saveCode call sites`; `packages/openauth/src/ports/token-store.ts` (relax `saveCode` to plain bytes / payload)
- **Problem:** Three adapters import `encryptPayload` / `decryptPayload` from `domain/crypto` and call them inside their `saveCode` / `consumeCode`. A 4th-party adapter could store plaintext and still satisfy the typed port. The encryption invariant is enforced by adapter-author discipline.
- **Fix:** Encrypt at the call site in `domain/token.ts` before calling `tokenStore.saveCode(code, ciphertext, ttl)`. Decrypt after `consumeCode` returns. Reduce the port to a plain KV.
- **Verification note:** Confirmed via grep.

### M2 — Wire `peekRefresh` into `ports/CONSISTENCY.md`

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/ports/CONSISTENCY.md`; `packages/openauth/src/ports/token-store.ts:159-167`; `packages/openauth/test/ports/token-store.ts` (assertion)
- **Problem:** Phase-8-shipped `peekRefresh` is load-bearing for both `/revoke` and refresh-grant client auth, but has no row in `CONSISTENCY.md`. Port docstring says "Eventual consistency is acceptable" — which **is** safe given `consumeRefresh` is strong (the failure mode is benign `invalid_grant`), but the doc gap is real.
- **Fix:** Add the row. State explicitly that eventual is acceptable, document why (consume is the strong gate), and add a conformance test that races peek → consume.
- **Verification note:** Confirmed by grep — no entry in CONSISTENCY.md.

### M3 — Deduplicate `AUTH_CODE_MAX_TTL_MS` across adapters

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/adapters/{memory:556, d1:22, dynamo:299, postgres:745}/token-store.ts`; canonical source `packages/openauth/src/domain/authorize.ts` (export)
- **Problem:** Each adapter declares its own `const AUTH_CODE_MAX_TTL_MS = 60_000`. The canonical value is `AUTH_CODE_TTL_MS` in `domain/authorize.ts`. If the OAuth 2.1 BCP ceiling were ever changed (testing, future spec drift), the adapters silently enforce a different limit than the domain uses.
- **Fix:** Import the shared constant. Add a comment that it's the OAuth 2.1 BCP ceiling.
- **Verification note:** Confirmed.

### M4 — Use exported `DEFAULT_ACCESS_TTL_MS` / `DEFAULT_REFRESH_TTL_MS` at the fallback site

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/domain/token.ts:192-193` (fallback); `domain/token.ts:1047-1048` (canonical constants)
- **Problem:** `mintTokens` falls back to inline literals (`15 * 60`, `30 * 24 * 60 * 60`) rather than the exported `DEFAULT_ACCESS_TTL_MS` / `DEFAULT_REFRESH_TTL_MS`. Drift will not be caught.
- **Fix:** `const accessTtl = tenant.config.accessTtl ? tenant.config.accessTtl * 1000 : DEFAULT_ACCESS_TTL_MS` (and refresh).
- **Verification note:** Confirmed.

### M5 — `mintTokens` should carry forward original `methodId` / `methodKind` on refresh

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/domain/refresh.ts:131-137`; `packages/openauth/src/types/token.ts` (consider grant-origin claim)
- **Problem:** Refresh-grant stamps rotated tokens with `methodId: "refresh", methodKind: "refresh"` — loses original method provenance and collides with the host's URL-routing space (a tenant could register a method with `id: "refresh"`).
- **Fix:** Either (a) carry `payload.methodId` / `payload.methodKind` from the consumed refresh payload into the next mint; OR (b) introduce a `grantOrigin: "code" | "refresh" | "exchange"` JWT claim distinct from `mid` / `mkind` and stamp the original method id/kind. (a) is the smaller change.
- **Verification note:** Confirmed.

### M6 — Tighten `IdP` type to match `createIdP`'s actual return shape

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/types/idp.ts:223-236`; `packages/openauth/src/index.ts:230-239`
- **Problem:** `IdP.revoke?` / `introspect?` typed optional but `createIdP` always assigns; `par?` is in the type but never returned. Callers that switch on the optionality get useless conditionals.
- **Fix:** Mark `revoke` and `introspect` non-optional. Remove `par?` until it ships (Phase 8 follow-up).
- **Verification note:** Confirmed.

### M7 — Fix `tenantId: string` parameter + `as never` cast in `clientCredentialsGrant`

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/domain/client-credentials.ts:62-65`
- **Problem:** Function signature `tenantId: string` (not `TenantId`); call site uses `getTenantConfig(tenantId as never)`. Type hole — a caller passing an unbranded string bypasses the branding guarantee.
- **Fix:** Change parameter type to `TenantId`. The caller in `http/handlers/token.ts` already has a branded value from `resolveTenant`.
- **Verification note:** Confirmed.

### M8 — Validate / encode cookie names

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/http/cookies.ts:60`
- **Problem:** `${cookie.name}=${encodeURIComponent(value)}` — the name is template-spliced raw. RFC 6265 §4.1 prohibits several characters in cookie names. Internal callers are safe (fixed names like `auth.flow`); host-supplied names via method `MethodResult.setCookies` are not.
- **Fix:** Lightweight validator: reject names containing `=;,` or whitespace. Or `assertCookieName(cookie.name)` helper that throws clearly.
- **Verification note:** Confirmed.

### M9 — Allow `cookieDefaults.secure` override for local-HTTP development

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/index.ts:223`; `packages/openauth/src/types/idp.ts` (extend `IdPOptions`)
- **Problem:** `cookieDefaults: { secure: true }` hardcoded with no override. Chrome rejects `Secure` cookies over HTTP, so `idp.flow` and other framework cookies fail on `localhost`. INTEGRATION.md §17 walks a steel-thread that exercises the cookie path and would fail locally.
- **Fix:** Add `IdPOptions.cookies?: { secure?: boolean; domain?: string; path?: string }`. Default `secure: true` but allow opt-out.
- **Verification note:** Confirmed.

### M10 — Re-export picker types from `index.ts`

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/index.ts` (add exports); `packages/openauth/src/types/idp.ts:263` (currently `import type { PickerContext, PickerMethod } from "../ui/picker"`); also consider moving the types into `types/`
- **Problem:** `IdPOptions.renderPicker: RenderPicker` is public surface, but `RenderPicker` / `PickerMethod` / `PickerContext` aren't re-exported. Consumers must inline-type or deep-import. There's also a minor `types/` → `ui/` cross-layer dependency.
- **Fix:** Add to `export type { … } from "./types/idp"` (or wherever they ultimately live). Optionally move `PickerMethod` / `PickerContext` into `types/picker.ts` and have `ui/picker.ts` import them back — that closes the layer hygiene gap.
- **Verification note:** Confirmed.

### M11 — Either implement or strike the "warn on response sanitization" claim

- [ ] **Status:** not started
- **Severity:** Medium · **Effort:** S
- **Files:** `packages/openauth/src/http/cookies.ts:112-132`; `packages/openauth/ARCHITECTURE.md` line ~175-179
- **Problem:** ARCHITECTURE.md promises "logging a programmer-bug warning at ERROR level" when method-returned responses include stripped headers. The implementation silently drops them. A method that tries to set CSP / Set-Cookie via `Response.headers` will fail silently — real footgun.
- **Fix:** Either add `console.warn` (cheap, ships today) or wait for the Logger port (Phase 8 follow-up) and gate it through that. If neither is happening soon, strike the line from ARCHITECTURE.md and document the silent strip in INTEGRATION.md §13.
- **Verification note:** Confirmed at code.

---

## Low — defense-in-depth / housekeeping

### L1 — Wire or delete `revokeAllForSubject`

- [ ] **Status:** not started
- **Severity:** Low · **Effort:** S
- **Files:** `packages/openauth/src/domain/revoke.ts:122-138`
- **Problem:** Exported, but the only callers are tests. ARCHITECTURE / refresh.ts comments suggest it's meant for reuse-detection escalation; reuse detection currently revokes only the family (which is handled inside the adapter's `consumeRefresh` already).
- **Fix:** Decide: (a) wire into the reuse-detection escalation path in `refresh.ts:93-103`, OR (b) delete the function. Document the decision in ARCHITECTURE.md.
- **Verification note:** Confirmed dead in `src/`; only test callers.

### L2 — Move `domain/password-hash.ts` to `methods/`

- [ ] **Status:** not started
- **Severity:** Low · **Effort:** S
- **Files:** `packages/openauth/src/domain/password-hash.ts`; `packages/openauth/src/methods/password.ts`; `packages/openauth/src/index.ts` (re-export path)
- **Problem:** Only imported by `methods/password.ts` and `src/index.ts`. Argon2id hashing is a method-specific concern, not a domain policy. Sitting under `domain/` is a layering smell.
- **Fix:** Move the file to `methods/password-hash.ts`. Update imports. Keep the public re-export from `index.ts` — only the file location changes.
- **Verification note:** Confirmed by inspection.

### L3 — Make ARCHITECTURE.md / INTEGRATION.md honest about methods importing helpers

- [ ] **Status:** not started
- **Severity:** Low · **Effort:** S
- **Files:** `packages/openauth/ARCHITECTURE.md` line 42-47; `packages/openauth/src/types/method.ts:7-8`; check imports in `packages/openauth/src/methods/{password,code,passkey}.ts`
- **Problem:** ARCHITECTURE.md says methods "import only Web Fetch `Request`/`Response` and the types in `src/types/`." In reality `methods/code.ts`, `methods/password.ts` import `base64url`, `sha256`, `randomBytes`, `timingSafeEqualStr`, `argon2idHasher` from `domain/crypto` + `domain/password-hash`; `methods/passkey.ts:35` imports from `ui/forms`.
- **Fix:** Restate the contract: methods may import `types/`, `domain/{crypto,password-hash}`, `ui/forms`; not adapters, not `http/`. Or move the helpers into `methods/` (L2 covers password-hash; crypto helpers could move to a `methods/lib/` if a stricter line is wanted). A CI lint rule on the agreed contract would prevent drift.
- **Verification note:** Confirmed via grep on `methods/*.ts` imports.

### L4 — Expand public-API third-party type-leak guard

- [ ] **Status:** not started
- **Severity:** Low · **Effort:** S
- **Files:** `packages/openauth/test/types/public-api-no-thirdparty-leaks.test.ts`
- **Problem:** Test probes `Oauth2Properties.idTokenClaims`, `Oauth2MethodInput.deriveSubject`, `IdP.handle`, `IdPOptions.resolveTenant`, `SuccessMapInput.properties`, `Oauth2FactoryConfig`, `OidcFactoryConfig`. INTEGRATION.md §16 promises additional surfaces are clean (`AuthMethodFactory.configSchema`, `KeyStore.SigningKey.privateKeyRef` / `publicJwk`, `AuditEvent`, `MethodConfig`) but they're not probed.
- **Fix:** Add `assertAssignable` lines or property-shape probes for the missing types.
- **Verification note:** Confirmed by reading the test.

### L5 — Document rate-limiting / unauth-endpoint gap prominently in INTEGRATION.md

- [ ] **Status:** not started
- **Severity:** Low · **Effort:** S
- **Files:** `packages/openauth/INTEGRATION.md` §15 ("Phase 8 features that are NOT yet in the library")
- **Problem:** Rate-limiter port is intentionally deferred to Phase 8, but the current note is a parenthetical. `/authorize`, `/login`, `/passkey/*`, `/code/*` are unprotected at the library layer. Hosts deploying without an upstream WAF / CDN ratelimit are exposed.
- **Fix:** Promote to a callout in §15. Be explicit: until the port lands, **deploy behind a rate-limiting proxy**. Reference the specific endpoints that need protection.
- **Verification note:** Documentation gap, no code change.

### L6 — Audit-log error swallowing should at least `console.error` until Logger port lands

- [ ] **Status:** not started
- **Severity:** Low · **Effort:** S
- **Files:** `packages/openauth/src/domain/authorize.ts:399` (and similar `audit(...)` helpers in `refresh.ts:184`, `revoke.ts:148`)
- **Problem:** `await deps.auditLog.log(event)` is wrapped in `try { … } catch { /* swallow */ }`. Audit gaps are silent. Operators have no way to know when the audit pipeline is down.
- **Fix:** Add `console.error` (or a guarded `process.env.OPENAUTH_DEBUG`) on swallow until the Logger port arrives. Replace with the proper port when it ships.
- **Verification note:** Confirmed at multiple sites by grep.

---

## Out-of-scope / informational

These came up in review but are **not action items** — either intentionally deferred or correct-as-written. Captured here so they don't get re-raised.

- **State envelope has no `iat`/`exp`** — by design. The `FlowRecord` TTL is the only bound, and the envelope carries no sensitive data. Acceptable per ARCHITECTURE.md "Why a global state key."
- **JWE `kid` accepted without allowlist** (`domain/crypto.ts:142-160`) — bounded by `KeyStore.getEncryptionKey(kid)` returning a key. Defense-in-depth opportunity; not a real threat in current scope.
- **Code modulo bias for 7+ digit codes** (`methods/code.ts:328-336`) — bias is ~0.02% at 6 digits; codeLength is capped at 10 in the schema. Not a meaningful issue unless someone reaches for 10-digit codes in production.
- **M2M `verify` hook receives plaintext `client_secret`** (`domain/client-credentials.ts:130-134`) — minor leak surface, but the framework has already authenticated by this point. Strip if you want to reduce blast radius, but no actual vulnerability.
- **`parseBasicAuth` decode failure silently falls back to form body** (`domain/client-auth.ts:71-94`) — minor robustness issue. Real-world impact small.
- **Passkey origin not cross-checked against request host** — WebAuthn's signed `clientData.origin` is the primary protection inside `@simplewebauthn/server`. Library gap only matters if operator misconfigures `config.origins`; that's a config-management problem, not a library bug.
- **OAuth 2.1 conformance posture, refresh rotation, PKCE type-system enforcement, `TenantId` opacity, the `id`/`kind` split** — all reviewed and **working correctly**. The rebuild's structural integrity is solid; these are not findings, they're confirmations.

---

## Effort & sequencing summary

If you take them in this order, you ship the security-critical work first while picking up cheap wins as you go:

1. **Day 1 (~4h):** H2, H3, H4, H8, H1 — small security/correctness fixes (S-effort).
2. **Day 2 (~6h):** C2 (Dynamo race), H6 (introspect order), H9 (audit type), M3-M10 cluster of small fixes.
3. **Day 3-4 (~12h):** C1 (KeyStore at-rest), H5 (m2m tenant resolution), H7 (MethodCache invalidation), H10 (typed reuse signal), H11 (skip-refresh on m2m).
4. **Day 5+ (M-L effort, mostly refactor):** M1 (encrypt at domain boundary), H12 (decide `request.custom`), L tier.

Total estimated effort: **~5 focused days** for everything Critical + High + the cheap Medium fixes. Pure-Medium / Low tail is another 1-2 days of cleanup.
