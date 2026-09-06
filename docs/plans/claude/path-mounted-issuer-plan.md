# Brief: the IdP cannot be mounted under a path prefix

## Symptom

Deploy the IdP behind a reverse proxy at a path prefix — `issuerUrl =
https://example.com/idp`, proxy strips `/idp` before forwarding — and:

- Every login form posts to `https://example.com/m/<method>/send` and 404s.
  No sign-in of any kind can complete.
- The `redirect_uri` sent to upstream providers is
  `https://example.com/cb/<method>`, missing `/idp`. Okta/Google/Cognito
  return the user to a 404.
- SAML SP metadata advertises an SLS URL with the same defect.

Routing and token signing are fine. `iss` is correct, discovery is correct,
`/idp/authorize` and `/idp/token` work. Only URLs the library _emits_ are wrong.

## Root cause

The library assumes it owns the origin root. Two families, both losing
`issuerUrl`'s pathname.

**A. Method form actions — path-absolute string literals (7 sites)**

    methods/code.ts:128,172,196,274       action: `/m/${id}/send` | `/verify`
    methods/password.ts:143,262           action: `/m/${methodId}/login`
    methods/passkey.ts:154                action: `/m/${id}/authenticate-options`

**B. Callback URLs — rebuilt from protocol + host, which discards the path**

    domain/authorize.ts:205-206           SOURCE OF TRUTH (see note below)
    http/handlers/method-route.ts:60      mirrors it for public routes
    domain/callback.ts:368                mirrors it for unsolicited callbacks
    methods/saml-sp/metadata.ts:187       slsUrl, same construction

Family B's shape:

    const callbackHost = deps.callbackHostFor?.(tenant.id) ?? new URL(deps.issuerUrl).host
    const callbackPath = `/cb/${methodId}`
    const callbackUrl  = `${new URL(deps.issuerUrl).protocol}//${callbackHost}${callbackPath}`

`protocol` + `host` is scheme and authority only. Any path on `issuerUrl` is
dropped, exactly as `URL.origin` would drop it.

B is the more serious family: that URL is registered in a third party's
configuration, so it cannot be corrected by rewriting responses afterwards.

## What makes this cheap

`issuerUrl` is already in scope at every site. Nothing needs threading through:

- `MethodContext.issuerUrl` — `types/method.ts:192`, already documented as
  "the issuer URL of this IdP"
- `deps.issuerUrl` in `domain/authorize.ts`
- `c.get("issuerUrl")` in `http/handlers/method-route.ts`

## Required behaviour

Derive the mount prefix from `issuerUrl.pathname` and prepend it wherever the
library emits one of its own routes.

    issuerUrl                      mount prefix   form action                  callback
    https://example.com            ""             /m/code/send                 https://example.com/cb/oidc
    https://example.com/idp        "/idp"         /idp/m/code/send             https://example.com/idp/cb/oidc
    https://example.com/idp/       "/idp"         /idp/m/code/send             https://example.com/idp/cb/oidc

Normalise: strip trailing slashes; a pathname of `/` must yield `""`, not `"/"`,
so root-mounted deployments emit byte-identical URLs to today.

**Root-mounted output must not change.** That is the regression bar — most
existing deployments are root-mounted and their registered `redirect_uri`s must
keep working untouched.

## Design decision you must make (do not guess)

`callbackHostFor(tenantId)` lets a deployment serve callbacks on a _different
host_ from the issuer. When it returns a host and `issuerUrl` also has a path,
which wins?

- Applying the issuer's path assumes the override host is mounted the same way.
- Ignoring it assumes the override host is root-mounted.

Neither is obviously right. Find why `callbackHostFor` exists (git history,
tests, callers), decide deliberately, and document it on the option's JSDoc.
Whatever you choose, the three Family-B sites must agree — see below.

## Constraints

- `domain/authorize.ts:205` is the source of truth for callback derivation. The
  comment at `http/handlers/method-route.ts:57` says so, and `metadata.test.ts`
  is an anti-drift test asserting the emitted SAML entityID/ACS equal what
  `buildAuthnRequestRedirect` derives. Keep all Family-B sites deriving through
  one shared helper rather than fixing them individually, or that test is the
  only thing standing between you and three implementations that disagree.
- The library owns the protocol; the host owns its tables. Do not add a
  `basePath` option — `issuerUrl` already carries this information and a second
  source would let the two disagree.

## Verification

1. Unit: mount prefix derivation for `""`, `/`, `/idp`, `/idp/`, `//idp//`.
2. Unit: with `issuerUrl` root-mounted, every emitted URL is byte-identical to
   the current output. Snapshot before changing anything.
3. Unit: with `issuerUrl = https://x/idp`, form actions start `/idp/m/` and
   callbacks start `https://x/idp/cb/`.
4. Anti-drift: `metadata.test.ts` still passes, i.e. SAML metadata agrees with
   `buildAuthnRequestRedirect` under a path-mounted issuer too.
5. End to end, the only check that would have caught this: run the IdP behind a
   proxy at `/idp` and complete a real code login. Health checks, discovery and
   token signing all pass while this bug is present.

## Out of scope

Do not change routing, the router's mount points, or the shape of `issuerUrl`.
The service continues to serve `/m/*` and `/cb/*` at its own root; the proxy
strips the prefix. This is only about the URLs the library hands to browsers and
to upstream providers.

## Downstream note

Consumers currently work around this by routing `/m/*` and `/cb/*` at their
proxy in addition to the mounted prefix. Once this ships, those extra routes can
be deleted — mention it in the changelog. Anyone with a registered upstream
`redirect_uri` must update it to the prefixed form, so this is a breaking change
for path-mounted deployments with external providers configured.
