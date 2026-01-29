# Multi-Tenant Support Features for OpenAuth

## Overview

Add three features to support dynamic multi-tenant applications:

1. Dynamic `basePath` option
2. Cookie configuration (path and domain)
3. Request context mechanism

## Goal

Enable usage like:

```ts
type AppContext = { orgSlug: string; appSlug: string }

const appAuthIssuer = issuer({
  subjects,
  storage,
  basePath: (req) =>
    `/auth/${req.headers.get("x-org-slug")}/${req.headers.get("x-app-slug")}`,
  cookies: {
    path: "/",
    domain: ".yourauth.com", // Optional: for cross-subdomain
  },
  context: (req) => ({
    orgSlug: req.headers.get("x-org-slug")!,
    appSlug: req.headers.get("x-app-slug")!,
  }),
  providers: async (ctx) => {
    const { orgSlug, appSlug } = ctx.get("context") // Type-safe access
    const org = await getOrganizationBySlug(orgSlug)
    const app = await getApplicationByOrgAndSlug(org.organizationId, appSlug)
    // ... return providers
  },
  success: async (response, input, req) => {
    // context is part of input object (like tenantId)
    const { orgSlug, appSlug } = input.context
    return response.subject("user", { userId: "...", orgSlug, appSlug })
  },
})

app.route("/auth/:orgSlug/:appSlug", appAuthIssuer)
```

## Backward Compatibility Strategy

All new features are optional with sensible defaults:

- `basePath`: defaults to `""` (current behavior)
- `cookies.path`: defaults to `undefined` (current behavior - Hono's default)
- `cookies.domain`: defaults to `undefined` (current behavior)
- `context`: defaults to `undefined` (no custom context)

---

## Security Considerations

### Risk Assessment

| Feature  | Risk Level | Attack Vector                        | Mitigation                               |
| -------- | ---------- | ------------------------------------ | ---------------------------------------- |
| basePath | **Medium** | Path injection via malicious headers | Regex validation of path format          |
| cookies  | **Low**    | Overly broad domain config           | Documentation + optional warning         |
| context  | **Low**    | Trusting unvalidated header data     | Documentation (developer responsibility) |

### Security Mitigations

**1. basePath Validation (Required)**

The basePath can be derived from user-controlled headers, making it a potential injection vector:

- Open redirect: `x-org-slug: /../../../evil.com`
- Issuer URL manipulation in JWTs

**Implementation:**

```ts
// Only allow: empty string, or paths like /foo, /foo/bar, /foo-bar/baz_123
const VALID_BASE_PATH_REGEX = /^(\/[a-zA-Z0-9_-]+)*$/

const resolveBasePath = (req: Request): string => {
  if (!input.basePath) return ""
  const base =
    typeof input.basePath === "string" ? input.basePath : input.basePath(req)

  // Security: Reject invalid basePath to prevent path injection
  if (base && !VALID_BASE_PATH_REGEX.test(base)) {
    console.error("Invalid basePath rejected:", base)
    return "" // Safe fallback
  }
  return base
}
```

**2. Cookie Domain Warning (Optional)**

Warn developers about overly broad cookie domains:

```ts
if (input.cookies?.domain) {
  const parts = input.cookies.domain.replace(/^\./, "").split(".")
  if (parts.length < 2 || (parts.length === 2 && parts[1].length <= 3)) {
    console.warn(
      "OpenAuth: Cookie domain may be too broad:",
      input.cookies.domain,
      "- this could expose cookies to unintended sites",
    )
  }
}
```

**3. Context Security Documentation**

Add JSDoc warnings to make developers aware:

```ts
/**
 * Extract custom context from each request.
 *
 * @security Context data typically comes from request headers which may be
 * user-controlled (e.g., set by a malicious client). Always validate context
 * values before:
 * - Using them in database queries (SQL injection risk)
 * - Including them in JWT claims (token pollution)
 * - Using them in redirects (open redirect risk)
 *
 * @example
 * context: (req) => {
 *   const orgSlug = req.headers.get("x-org-slug")
 *   // Validate before trusting!
 *   if (!orgSlug || !/^[a-z0-9-]+$/.test(orgSlug)) {
 *     throw new Error("Invalid org slug")
 *   }
 *   return { orgSlug }
 * }
 */
context?: (req: Request) => RequestContext
```

---

## Feature 1: Dynamic basePath

### Design Decision: basePath vs Tenant Routes

**Important**: `basePath` and the existing `/tenant/:tenantId/*` routes serve different purposes:

| Feature               | Purpose                                          | When to Use                                              |
| --------------------- | ------------------------------------------------ | -------------------------------------------------------- |
| `basePath`            | Dynamic URL prefix for the entire issuer         | When mounting at dynamic paths (e.g., `/auth/:org/:app`) |
| `/tenant/:tenantId/*` | Built-in tenant isolation within a single issuer | When using path-based tenant identification              |

**Interaction**: These features are **composable**. If both are used:

- basePath: `/auth/acme/myapp`
- Tenant route: `/tenant/tenant123/authorize`
- Full path: `/auth/acme/myapp/tenant/tenant123/authorize`

The basePath is prepended to ALL routes, including tenant routes.

### Changes Required

**File: `packages/openauth/src/issuer.ts`**

1. **Add to IssuerInput interface** (~line 532):

```ts
/**
 * Base path prefix for all routes and URLs. Can be a static string or a
 * function that receives the request and returns the path.
 *
 * Use this when mounting the issuer at a dynamic path that includes
 * request-specific information (e.g., org/app slugs from headers).
 *
 * @security The basePath is validated to only contain safe path segments
 * (alphanumeric, dash, underscore). Invalid paths are rejected and fall
 * back to empty string. This prevents path injection attacks when basePath
 * is derived from user-controlled headers.
 *
 * @example
 * // Static path
 * basePath: "/auth/v1"
 *
 * // Dynamic path from headers (validated automatically)
 * basePath: (req) => `/auth/${req.headers.get("x-org-slug")}`
 */
basePath?: string | ((req: Request) => string)
```

2. **Add helper to resolve basePath with validation** (~line 550):

```ts
// Security: Only allow safe path characters
const VALID_BASE_PATH_REGEX = /^(\/[a-zA-Z0-9_-]+)*$/

const resolveBasePath = (req: Request): string => {
  if (!input.basePath) return ""
  const base =
    typeof input.basePath === "string" ? input.basePath : input.basePath(req)

  // Security: Reject invalid basePath to prevent path injection
  if (base && !VALID_BASE_PATH_REGEX.test(base)) {
    console.error("Invalid basePath rejected:", base)
    return "" // Safe fallback rather than throwing
  }
  return base
}
```

3. **Modify issuer() helper function** (line 830-832):

```ts
function getIssuerUrl(ctx: Context): string {
  const base = resolveBasePath(ctx.req.raw)
  const origin = new URL(getRelativeUrl(ctx, "/")).origin
  return base ? `${origin}${base}` : origin
}
```

4. **Update internal redirects** to use basePath:

Location: Lines 1235, 1239, 1316, 1320

```ts
// Before:
return c.redirect(`/${provider}/authorize`)

// After:
return c.redirect(`${resolveBasePath(c.req.raw)}/${provider}/authorize`)
```

For tenant routes:

```ts
// Before:
return c.redirect(`/tenant/${tenantId}/${provider}/authorize`)

// After:
return c.redirect(
  `${resolveBasePath(c.req.raw)}/tenant/${tenantId}/${provider}/authorize`,
)
```

5. **Update metadata endpoints** (lines 885-896):

```ts
const metadataHandler = async (c: Context) => {
  const iss = getIssuerUrl(c)
  return c.json({
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/token`,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    response_types_supported: ["code", "token"],
    id_token_signing_alg_values_supported: ["ES256"],
    subject_types_supported: ["public"],
  })
}
```

Note: Since `iss` already includes the basePath, endpoints are just appended.

---

## Feature 2: Cookie Configuration

### Expanded Scope

Support both `path` and `domain` for multi-tenant scenarios where:

- `path: "/"` - Cookies work across all sub-paths
- `domain: ".yourauth.com"` - Cookies work across subdomains

### Changes Required

**File: `packages/openauth/src/issuer.ts`**

1. **Add to IssuerInput interface** (~line 532):

```ts
/**
 * Cookie configuration options for the authorization flow.
 *
 * @example
 * cookies: {
 *   path: "/",           // Root path for cross-path access
 *   domain: ".example.com" // Cross-subdomain access
 * }
 */
cookies?: {
  /**
   * Path for cookies. Set to "/" for root-level cookies that work
   * across all paths. Defaults to Hono's default (current path).
   */
  path?: string
  /**
   * Domain for cookies. Use leading dot for subdomain access
   * (e.g., ".example.com"). Defaults to current domain.
   */
  domain?: string
}
```

2. **Modify auth.set()** (lines 696-703):

```ts
async set(ctx, key, maxAge, value) {
  setCookie(ctx, key, await encrypt(value), {
    maxAge,
    httpOnly: true,
    path: input.cookies?.path,
    domain: input.cookies?.domain,
    ...(ctx.req.url.startsWith("https://")
      ? { secure: true, sameSite: "None" }
      : {}),
  })
}
```

3. **Modify auth.unset()** (lines 712-714):

```ts
async unset(ctx: Context, key: string) {
  deleteCookie(ctx, key, {
    path: input.cookies?.path,
    domain: input.cookies?.domain,
  })
}
```

---

## Feature 3: Request Context Mechanism

### Type-Safe Design

The key challenge is making context type-safe throughout the flow. We'll:

1. Add a `RequestContext` generic to the issuer function
2. Extend Hono's Variables type to include the context
3. Provide type-safe access via `ctx.get("context")`

### Changes Required

**File: `packages/openauth/src/issuer.ts`**

1. **Update issuer function signature** (~line 537):

```ts
export function issuer<
  Providers extends Record<string, Provider<any>>,
  Subjects extends SubjectSchema,
  RequestContext = undefined,
  Result = {
    [key in keyof Providers]: Prettify<
      {
        provider: key
        tenantId?: string
      } & (RequestContext extends undefined
        ? {}
        : { context: RequestContext }) &
        (Providers[key] extends Provider<infer T> ? T : {})
    >
  }[keyof Providers],
>(input: IssuerInput<Providers, Subjects, RequestContext, Result>)
```

2. **Add to IssuerInput interface**:

```ts
/**
 * Extract custom context from each request. The context is available:
 * - In providers: `ctx.get("context")`
 * - In success/refresh callbacks: `input.context`
 *
 * @security Context data typically comes from request headers which may be
 * user-controlled. Always validate context values before using them in
 * database queries (SQL injection), JWT claims (token pollution), or
 * redirects (open redirect).
 *
 * @example
 * context: (req) => {
 *   const orgSlug = req.headers.get("x-org-slug")
 *   // Validate before trusting!
 *   if (!orgSlug || !/^[a-z0-9-]+$/.test(orgSlug)) {
 *     throw new Error("Invalid org slug")
 *   }
 *   return { orgSlug }
 * }
 */
context?: (req: Request) => RequestContext
```

3. **Update Hono app Variables type** (lines 834-838):

```ts
const app = new Hono<{
  Variables: {
    authorization: AuthorizationState
    tenantId: string
    provider: string
    context: RequestContext
  }
}>().use(logger())
```

4. **Add context extraction middleware** (after app creation, ~line 840):

```ts
if (input.context) {
  app.use(async (c, next) => {
    c.set("context", input.context!(c.req.raw))
    await next()
  })
}
```

5. **Update success callback invocations**:

In `auth.success()` (line 621):

```ts
return await input.success(
  { async subject(...) { ... } },
  {
    provider: ctx.get("provider"),
    tenantId: authorization.tenantId,
    ...(input.context ? { context: ctx.get("context") } : {}),
    ...properties,
  },
  ctx.req.raw,
)
```

In client_credentials flow (line 1150):

```ts
return input.success(
  { async subject(...) { ... } },
  {
    provider: provider.toString(),
    ...(input.context ? { context: c.get("context") } : {}),
    ...response,
  },
  c.req.raw,
)
```

6. **Update refresh callback** (line 1080):

```ts
return input.refresh(
  { async subject(...) { ... } },
  {
    type: payload.type,
    properties: payload.properties,
    subject: payload.subject,
    clientID: payload.clientID,
    ...(input.context ? { context: c.get("context") } : {}),
  },
  c.req.raw,
)
```

### Usage Examples

**In providers (Hono Context):**

```ts
providers: async (ctx) => {
  // Type-safe: ctx.get("context") returns RequestContext
  const { orgSlug, appSlug } = ctx.get("context")
  // ...
}
```

**In success callback (input object):**

```ts
success: async (response, input, req) => {
  // Type-safe: input.context is RequestContext
  const { orgSlug, appSlug } = input.context
  // ...
}
```

**In refresh callback:**

```ts
refresh: async (response, input, req) => {
  // Context from the refresh request (may differ from original auth)
  const { orgSlug } = input.context
  // ...
}
```

---

## Files to Modify

1. **`packages/openauth/src/issuer.ts`** - Main implementation (~15-20 changes)
2. **`packages/openauth/test/issuer.test.ts`** - Add tests for cookie config
3. **`packages/openauth/test/dynamic-providers.test.ts`** - Add basePath and context tests

---

## Test Plan

### Unit Tests to Add

**1. basePath tests** (in `dynamic-providers.test.ts`):

```ts
describe("basePath", () => {
  test("static basePath is included in redirects", async () => { ... })
  test("dynamic basePath function is called per request", async () => { ... })
  test("basePath is included in metadata endpoints", async () => { ... })
  test("basePath composes with tenant routes", async () => { ... })
  test("empty basePath (default) maintains current behavior", async () => { ... })

  // Security tests
  test("rejects basePath with path traversal (/../)", async () => { ... })
  test("rejects basePath with invalid characters", async () => { ... })
  test("rejects basePath with protocol injection", async () => { ... })
  test("falls back to empty string on invalid basePath", async () => { ... })
})
```

**2. Cookie config tests** (in `issuer.test.ts`):

```ts
describe("cookie configuration", () => {
  test("custom cookie path is applied to set-cookie header", async () => { ... })
  test("custom cookie domain is applied", async () => { ... })
  test("cookie deletion uses same path/domain", async () => { ... })
  test("undefined config maintains current behavior", async () => { ... })
})
```

**3. Context tests** (in `dynamic-providers.test.ts`):

```ts
describe("request context", () => {
  test("context is extracted from request", async () => { ... })
  test("context is available in providers via ctx.get('context')", async () => { ... })
  test("context is available in success callback via input.context", async () => { ... })
  test("context is available in refresh callback", async () => { ... })
  test("undefined context maintains current behavior", async () => { ... })
})
```

### Manual Verification

```bash
cd packages/openauth && bun test
```

---

## Implementation Order

1. **Cookie configuration** (simplest, isolated changes)
2. **Request context mechanism** (builds on existing tenantId pattern)
3. **Dynamic basePath** (most pervasive, touches redirects and metadata)

Each feature should be committed separately for easy review and rollback.

---

## Summary of Key Decisions

| Decision                    | Choice                             | Rationale                              |
| --------------------------- | ---------------------------------- | -------------------------------------- |
| Context access in success   | `input.context`                    | Matches existing `tenantId` pattern    |
| Context access in providers | `ctx.get("context")`               | Uses Hono's typed Variables            |
| basePath + tenant routes    | Composable (basePath prefixes all) | Maximum flexibility                    |
| Cookie config scope         | `path` + `domain`                  | Covers multi-tenant scenarios          |
| Default behavior            | All features optional              | Full backward compatibility            |
| basePath security           | Regex validation + safe fallback   | Prevents path injection attacks        |
| Context security            | Documentation + examples           | Developer responsibility with guidance |
