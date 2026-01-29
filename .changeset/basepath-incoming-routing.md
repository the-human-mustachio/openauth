---
"@openauthjs/openauth": minor
---

Add automatic basePath stripping for incoming requests

When `basePath` is configured, OpenAuth now automatically strips the base path from incoming request URLs before internal routing. This enables cleaner integration when mounting the issuer at dynamic paths:

```typescript
// Before: Manual path stripping required
app.all("/auth/:orgSlug/:appSlug/*", (c) => {
  const basePath = `/auth/${c.req.param("orgSlug")}/${c.req.param("appSlug")}`;
  const url = new URL(c.req.url);
  url.pathname = url.pathname.replace(basePath, "") || "/";
  return appAuthIssuer.fetch(cloneRequestWithUrl(c.req.raw, url.toString()));
});

// After: Clean integration - no manual path stripping needed
app.all("/auth/:orgSlug/:appSlug/*", (c) => {
  c.req.raw.headers.set("x-org-slug", c.req.param("orgSlug"));
  c.req.raw.headers.set("x-app-slug", c.req.param("appSlug"));
  return appAuthIssuer.fetch(c.req.raw);
});
```

The `basePath` option now works symmetrically for both incoming and outgoing URLs.
