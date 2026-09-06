# Confirmed Post-Rebuild Review Findings

Date: 2026-09-06

Status: Confirmed against `@_mustachio/openauth` 0.13.3 (`7d03665`)

## Purpose

This document records issues found during a repository review and then
independently reproduced against the current implementation. The findings are
ordered by recommended remediation priority.

Baseline verification remained green:

- `bun test`: 788 passed, 0 failed.
- `bun run typecheck`: passed.
- The reproductions below were run without modifying the working tree.

## 1. `createClient.verify()` does not enforce token audience

**Severity:** High

`createClient()` is configured with a `clientID`, but `verify()` passes only the
issuer to `jose.jwtVerify()`. It neither checks the token's `aud` against
`input.clientID` nor honors `VerifyOptions.audience`.

Relevant code:

- `packages/openauth/src/client.ts:729-756`
- `packages/openauth/src/client.ts:784-789`

### Confirmed behavior

A client configured as `client-b` accepted a valid token issued with
`aud: "client-a"`. Supplying `{ audience: "client-b" }` to `verify()` did not
change the result.

```json
{
  "configuredClient": "client-b",
  "tokenAudience": "client-a",
  "acceptedNormally": true,
  "acceptedWithExplicitWrongAudience": true
}
```

This permits cross-client token confusion when multiple relying parties share
an issuer.

### Recommended remediation

- Pass an audience to `jwtVerify()`.
- Default it to `input.clientID`.
- If `VerifyOptions.audience` remains public, either honor it explicitly or
  remove it.
- Add a negative test proving that a correctly signed token for another client
  is rejected.

## 2. The advertised relying-party client flow is inconsistent with client requirements

**Severity:** High

The default `createClient().authorize()` call generates no PKCE verifier unless
`opts.pkce` is explicitly true. Public clients, however, always require PKCE.

For confidential clients, `ClientInput` has no client-secret field and
`exchange()` never sends a secret through HTTP Basic authentication or the form
body. Consequently, the default server-side flow shown in the README cannot
complete against a normal confidential client either.

Relevant code:

- `packages/openauth/src/client.ts:127-159`
- `packages/openauth/src/client.ts:597-627`
- `packages/openauth/src/client.ts:647-664`
- `README.md:138-163`

### Confirmed behavior

For a public client:

```json
{
  "pkceGenerated": false,
  "error": "invalid_request",
  "description": "client \"rp-1\" requires PKCE — missing code_challenge"
}
```

For a confidential client with PKCE disabled, authorization completed, but
`exchange()` returned `InvalidAuthorizationCodeError` because it presented no
client secret.

### Recommended remediation

- Make authorization-code flows use PKCE by default.
- Remove the unsupported `"token"` response option from the client API.
- Add an explicit confidential-client authentication configuration, preferably
  supporting `client_secret_basic` first.
- Use endpoints returned by discovery consistently.
- Correct the README result handling and add true `createClient.authorize()` →
  callback → `createClient.exchange()` tests for both public and confidential
  clients.

## 3. Invalid refresh scope consumes the refresh token

**Severity:** Medium

`refreshTokens()` peeks at the refresh payload, authenticates the client, and
checks DPoP before consumption. It then consumes the refresh token before
validating that a requested scope is a subset of the original grant.

Relevant code:

- `packages/openauth/src/domain/refresh.ts:64-128`
- `packages/openauth/src/domain/refresh.ts:148-162`

### Confirmed behavior

A request containing an ungranted scope returned `invalid_scope`. Retrying the
same token with no scope returned `invalid_grant` with a reuse signal:

```json
{
  "first": "invalid_scope",
  "retry": "invalid_grant",
  "reuse": true
}
```

Thus, a client typo can burn the token and make the next legitimate request
look like theft, potentially revoking the entire refresh family.

### Recommended remediation

- Compute and validate the requested scopes from `peekedPayload` before calling
  `consumeRefresh()`.
- Keep the atomic consume as the final gate immediately before minting the
  replacement tokens.
- Add a regression test proving that an `invalid_scope` response leaves the
  refresh token usable.

## 4. SAML `RelayState` is not considered during tenant middleware recovery

**Severity:** Medium

The SAML SP method carries the framework state envelope in `RelayState`, and
the callback domain correctly reads either `state` or `RelayState`. The tenant
middleware runs first, however, and its form-body extraction reads only
`state`.

Relevant code:

- `packages/openauth/src/http/router.ts:50-53`
- `packages/openauth/src/http/middleware/tenant.ts:173-210`
- `packages/openauth/src/domain/callback.ts:113-127`
- `packages/openauth/src/methods/saml-sp/authnrequest.ts:1-8`

### Confirmed behavior

With the same valid state envelope:

- Form field `RelayState` caused the middleware to invoke `resolveTenant` and
  fail there.
- Form field `state` bypassed `resolveTenant`, proving that the envelope was
  accepted by middleware recovery.

This breaks SP-initiated SAML callbacks when the host cannot independently
recover the tenant from the callback request. It is especially at odds with the
documented callback recovery guarantees.

### Recommended remediation

- Use one shared callback-state extraction helper in both middleware and the
  callback domain.
- For form-encoded POST callbacks, read `state ?? RelayState` from a cloned
  request body.
- Add an HTTP-level SP-initiated SAML test whose `resolveTenant` deliberately
  fails on callbacks, proving recovery comes from `RelayState`.

## 5. `IdPOptions.hooks` are accepted but never invoked

**Severity:** Medium

The public options type exposes `hooks.onSuccess` and `hooks.onFailure`, but
`createIdP()` does not propagate `opts.hooks` into `HttpDeps`, and no runtime
path invokes either hook.

Relevant code:

- `packages/openauth/src/types/idp.ts:331-335`
- `packages/openauth/src/index.ts:274-311`
- `packages/openauth/src/http/context.ts:40-73`

### Confirmed behavior

- A successful authorization and token issuance completed with
  `onSuccessCalls === 0`.
- A method denial returned `access_denied` with `onFailureCalls === 0`.

This is a silent API failure: configuration type-checks but has no effect.

### Recommended remediation

- Decide and document the exact lifecycle point and failure semantics for each
  observation hook.
- Propagate the hooks through the dependency graph and invoke them from shared
  success/failure paths.
- Because these are observation-only hooks, catch and report hook failures
  without changing protocol results.
- Add HTTP-level tests for success, denial, method error, and throwing hooks.

## 6. `subjects` is required but not used for server-side issuance validation

**Severity:** Medium

`IdPOptions.subjects` is required, but `createIdP()` never reads it. The server
therefore does not validate the `SubjectClaim` returned by `success()` before
placing it in access and refresh tokens.

Relevant code:

- `packages/openauth/src/types/idp.ts:318-327`
- `packages/openauth/src/index.ts:242-311`
- `packages/openauth/src/domain/token.ts:187-235`

### Confirmed behavior

With a subject schema requiring `{ id: string }`, a success callback returned
`{ wrong: 123 }`. Token issuance still returned HTTP 200. The relying-party
client may later reject the token, but malformed claims have already been
signed, persisted in the refresh payload, and exposed to other token consumers.

### Recommended remediation

- Validate `claim.type` exists in `subjects`.
- Validate `claim.properties` using the selected Standard Schema before
  persisting or signing tokens.
- Return a server-side error and emit a diagnostic event when the host's
  success callback violates its declared schema.
- Add issuance tests for unknown subject types and malformed properties.

## 7. Dynamic-registration credential generation is discarded

**Severity:** Low; API/documentation drift

`registerNewClient()` generates a client ID, client secret, secret hash, and
`ClientConfig`, but passes only `{ tenant, request }` to the host hook and then
discards the generated configuration with `void clientConfig`.

Relevant code:

- `packages/openauth/src/domain/register.ts:86-145`
- `packages/openauth/src/types/idp.ts:217-233`
- `packages/openauth/ARCHITECTURE.md:750-758`
- `packages/openauth/INTEGRATION.md:2023-2057`

### Confirmed behavior

Even with deterministic framework-generated credentials, the hook saw only
`tenant` and `request`, and the response used independently generated host
credentials:

```json
{
  "hookSaw": {
    "keys": ["tenant", "request"],
    "hasGeneratedId": false,
    "hasGeneratedSecret": false
  },
  "response": {
    "client_id": "host-id",
    "client_secret": "host-secret"
  }
}
```

The integration guide describes the actual host-generated behavior, while the
architecture and public type documentation say the framework supplies the
credentials.

### Recommended remediation

Choose one ownership model:

1. Framework-owned generation: pass the proposed `ClientConfig` and plaintext
   secret to the hook, then persist/return the hook-approved result; or
2. Host-owned generation: remove the unused generation code and test overrides,
   and update the architecture and type documentation.

The second option matches the current integration guide and is the smaller
change.

## Recommended implementation order

1. Enforce audience in `createClient.verify()`.
2. Repair and end-to-end test public and confidential RP client flows.
3. Move refresh-scope validation before token consumption.
4. Share callback state extraction so middleware recognizes `RelayState`.
5. Wire observation hooks and server-side subject validation.
6. Reconcile dynamic-registration ownership and remove dead code.
