---
"@openauthjs/openauth": minor
---

Add multi-tenant route support with `/tenant/:tenantId/authorize` pattern.

- Add `/tenant/:tenantId/authorize` route for tenant-specific auth flows
- Add `/tenant/:tenantId/:provider/*` routes for tenant-specific provider handling
- Pass `tenantId` to the `success` callback when using tenant routes
- Add `tenantId` to the `Result` type (available as `value.tenantId` in success callback)
- Add security validation to prevent tenant ID spoofing attacks
- Add tenant ID input validation (alphanumeric, underscore, hyphen, max 64 chars)

This enables multi-tenant OAuth flows in environments where subdomains or headers can't be used to identify tenants (e.g., AWS Lambda URLs).

Example usage:

```ts
const app = issuer({
  providers: async (ctx) => {
    const tenantId = ctx.get("tenantId") as string
    const config = await db.tenants.findUnique({ where: { id: tenantId } })
    return { github: GithubProvider({ clientID: config.githubClientId, ... }) }
  },
  success: async (ctx, value) => {
    return ctx.subject("user", { userID: value.email, tenantId: value.tenantId })
  }
})
```
