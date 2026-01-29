---
"@_mustachio/openauth": minor
---

Add multi-tenant support features:

- **`basePath`** - Dynamic base path for routes. Can be a static string or a function that returns the path based on the request. Useful when mounting the issuer at dynamic paths.

- **`cookies.path`** - Configure cookie path. Set to `"/"` for root-level cookies that work across all paths in multi-tenant setups.

- **`context`** - Extract custom context from requests. The context is available in providers via `ctx.get("requestContext")` and in the success callback via `value.context`.

Example usage:

```ts
const app = issuer({
  basePath: (req) => `/auth/${req.headers.get("x-org-slug")}`,
  cookies: { path: "/" },
  context: (req) => ({
    orgSlug: req.headers.get("x-org-slug")!,
  }),
  providers: async (ctx) => {
    const { orgSlug } = ctx.get("requestContext")
    // Load tenant-specific providers...
  },
  success: async (ctx, value) => {
    const { orgSlug } = value.context
    // Use context in success handler...
  },
})
```
