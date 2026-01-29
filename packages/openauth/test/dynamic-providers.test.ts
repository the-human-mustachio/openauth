import {
  expect,
  test,
  setSystemTime,
  describe,
  beforeEach,
  afterEach,
} from "bun:test"
import { object, string } from "valibot"
import { issuer } from "../src/issuer.js"
import { createSubjects } from "../src/subject.js"
import { MemoryStorage } from "../src/storage/memory.js"
import { Provider } from "../src/provider/provider.js"

const subjects = createSubjects({
  user: object({
    userID: string(),
  }),
})

const createDummyProvider = (email: string): Provider<{ email: string }> => ({
  type: "dummy",
  init(route, ctx) {
    route.get("/authorize", async (c) => {
      return ctx.success(c, {
        email,
      })
    })
  },
})

describe("dynamic providers", () => {
  beforeEach(async () => {
    setSystemTime(new Date("1/1/2024"))
  })

  afterEach(() => {
    setSystemTime()
  })

  test("resolves providers based on Host header (subdomains and custom domains)", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async (c) => {
        const host = c.req.header("host") || ""
        // Scenario 1: Custom Domain
        if (host === "auth.acme.com") {
          return {
            dummy: createDummyProvider("acme@custom.com"),
          }
        }
        // Scenario 2: Subdomain
        if (host.endsWith(".yourauth.com")) {
          const subdomain = host.replace(".yourauth.com", "")
          return {
            dummy: createDummyProvider(`${subdomain}@platform.com`),
          }
        }
        return {}
      },
      success: async (ctx, value) => {
        return ctx.subject("user", {
          userID: value.email,
        })
      },
    })

    // Test Custom Domain
    let response = await auth.request(
      "https://auth.acme.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      { headers: { Host: "auth.acme.com" } },
    )
    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toContain("/dummy/authorize")

    // Test Platform Subdomain
    response = await auth.request(
      "https://tenant-x.yourauth.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      { headers: { Host: "tenant-x.yourauth.com" } },
    )
    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toContain("/dummy/authorize")
  })

  test("returns 404 if provider not resolved for tenant", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async () => ({}), // No providers
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: "123" })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/dummy/authorize",
    )
    expect(response.status).toBe(404)
  })

  test("handles error thrown in provider factory", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async () => {
        throw new Error("Database connection failed")
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: "123" })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    // When an error happens during /authorize, it should redirect back with an OAuth error
    expect(response.status).toBe(302)
    const location = response.headers.get("location")!
    expect(location).toContain("error=server_error")
    expect(location).toContain("Database+connection+failed")
  })

  test("returns 404 for unknown provider even with dynamic factory", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async () => ({
        real: createDummyProvider("real@example.com"),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: "123" })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/fake/authorize",
    )
    expect(response.status).toBe(404)
  })
})

describe("tenant-specific routes", () => {
  beforeEach(async () => {
    setSystemTime(new Date("1/1/2024"))
  })

  afterEach(() => {
    setSystemTime()
  })

  test("tenant route resolves correct provider via path", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async (c) => {
        const tenantId = c.get("tenantId") as string | undefined
        return {
          dummy: createDummyProvider(`${tenantId || "unknown"}@test.com`),
        }
      },
      success: async (ctx, value) => {
        return ctx.subject("user", {
          userID: value.email,
        })
      },
    })

    // Test tenant authorize endpoint redirects to tenant provider
    const response = await auth.request(
      "https://auth.example.com/tenant/acme/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toContain(
      "/tenant/acme/dummy/authorize",
    )
  })

  test("tenantId is available in success callback", async () => {
    let receivedTenantId: string | undefined

    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async (c) => {
        const tenantId = c.get("tenantId") as string | undefined
        return {
          dummy: createDummyProvider(`${tenantId}@test.com`),
        }
      },
      success: async (ctx, value) => {
        receivedTenantId = value.tenantId
        return ctx.subject("user", {
          userID: value.email,
        })
      },
    })

    // Start auth flow
    const authorizeResponse = await auth.request(
      "https://auth.example.com/tenant/acme/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(authorizeResponse.status).toBe(302)

    // Get the authorization cookie
    const cookies = authorizeResponse.headers.get("set-cookie")

    // Follow redirect to provider authorize (which triggers success in dummy provider)
    const providerResponse = await auth.request(
      "https://auth.example.com/tenant/acme/dummy/authorize",
      { headers: { Cookie: cookies || "" } },
    )

    expect(receivedTenantId).toBe("acme")
  })

  test("rejects callback when tenantId in path differs from authorization cookie", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async (c) => ({
        dummy: createDummyProvider(
          `${(c.get("tenantId") as string) || "unknown"}@test.com`,
        ),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    // Step 1: Start auth flow on tenant "evil"
    const authorizeResponse = await auth.request(
      "https://auth.example.com/tenant/evil/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(authorizeResponse.status).toBe(302)

    // Get the authorization cookie from the response
    const cookies = authorizeResponse.headers.get("set-cookie")

    // Step 2: Try to use the cookie on a DIFFERENT tenant's callback
    // This simulates an attacker changing the URL path to "victim"
    const callbackResponse = await auth.request(
      "https://auth.example.com/tenant/victim/dummy/authorize",
      { headers: { Cookie: cookies || "" } },
    )

    // Should be rejected due to tenant mismatch
    expect(callbackResponse.status).toBe(302)
    const location = callbackResponse.headers.get("location")!
    expect(location).toContain("error=invalid_request")
    expect(location).toContain("Tenant")
  })

  test("returns 404 for unknown provider in tenant route", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async () => ({
        real: createDummyProvider("real@example.com"),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: "123" })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/tenant/acme/fake/authorize",
    )
    expect(response.status).toBe(404)
  })

  test("path traversal in URL is normalized before routing", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async () => ({
        dummy: createDummyProvider("test@example.com"),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    // URL normalization converts /tenant/../admin to /admin before routing
    // So it doesn't match the /tenant/:tenantId route at all (404)
    const response = await auth.request(
      "https://auth.example.com/tenant/../admin/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(404)
  })

  test("rejects tenantId with special characters", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async () => ({
        dummy: createDummyProvider("test@example.com"),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    // Test various injection attempts
    const maliciousTenantIds = [
      "tenant/../../etc",
      "tenant%2F%2Fevil",
      "<script>alert(1)</script>",
      "tenant;drop table users",
      "a".repeat(100), // Too long
    ]

    for (const tenantId of maliciousTenantIds) {
      const response = await auth.request(
        `https://auth.example.com/tenant/${encodeURIComponent(tenantId)}/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code`,
      )
      expect(response.status).toBe(400)
    }
  })

  test("accepts valid tenantId formats", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: async (c) => ({
        dummy: createDummyProvider(
          `${(c.get("tenantId") as string) || "unknown"}@test.com`,
        ),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    // Valid tenant IDs should work
    const validTenantIds = [
      "acme",
      "tenant-123",
      "TENANT_456",
      "a",
      "a".repeat(64), // Max length
    ]

    for (const tenantId of validTenantIds) {
      const response = await auth.request(
        `https://auth.example.com/tenant/${tenantId}/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code`,
      )
      expect(response.status).toBe(302) // Redirect to provider
    }
  })
})

describe("cookie path configuration", () => {
  beforeEach(async () => {
    setSystemTime(new Date("1/1/2024"))
  })

  afterEach(() => {
    setSystemTime()
  })

  test("custom cookie path is applied", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      cookies: {
        path: "/",
      },
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(302)
    const cookie = response.headers.get("set-cookie")
    expect(cookie).toContain("Path=/")
  })

  test("undefined cookie path uses default behavior", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(302)
    // Cookie should be set but without explicit Path=/
    const cookie = response.headers.get("set-cookie")
    expect(cookie).toBeTruthy()
  })
})

describe("request context mechanism", () => {
  beforeEach(async () => {
    setSystemTime(new Date("1/1/2024"))
  })

  afterEach(() => {
    setSystemTime()
  })

  test("context is extracted from request and available in success callback", async () => {
    let receivedContext: { orgSlug: string; appSlug: string } | undefined

    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      context: (req) => ({
        orgSlug: req.headers.get("x-org-slug") || "default-org",
        appSlug: req.headers.get("x-app-slug") || "default-app",
      }),
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        receivedContext = value.context
        return ctx.subject("user", { userID: value.email })
      },
    })

    // Start auth flow with custom headers
    const authorizeResponse = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      {
        headers: {
          "x-org-slug": "acme",
          "x-app-slug": "myapp",
        },
      },
    )
    expect(authorizeResponse.status).toBe(302)

    // Get the authorization cookie
    const cookies = authorizeResponse.headers.get("set-cookie")

    // Follow redirect to provider authorize (which triggers success)
    await auth.request("https://auth.example.com/dummy/authorize", {
      headers: {
        Cookie: cookies || "",
        "x-org-slug": "acme",
        "x-app-slug": "myapp",
      },
    })

    expect(receivedContext).toStrictEqual({
      orgSlug: "acme",
      appSlug: "myapp",
    })
  })

  test("context is available in providers function", async () => {
    let providerContext: { orgSlug: string } | undefined

    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      context: (req) => ({
        orgSlug: req.headers.get("x-org-slug") || "default-org",
      }),
      providers: async (c) => {
        providerContext = c.get("requestContext") as { orgSlug: string }
        return {
          dummy: createDummyProvider("test@example.com"),
        }
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      {
        headers: {
          "x-org-slug": "acme-corp",
        },
      },
    )

    expect(providerContext).toStrictEqual({
      orgSlug: "acme-corp",
    })
  })

  test("context is available in dynamic provider route handlers", async () => {
    let providerContextInRoute: { orgSlug: string } | undefined
    let successContext: { orgSlug: string } | undefined

    // Create a provider that captures context in its route handler
    const createContextAwareProvider = (): Provider<{ email: string }> => ({
      type: "context-aware",
      init(route, ctx) {
        route.get("/authorize", async (c) => {
          // Capture context inside the provider's route handler
          providerContextInRoute = c.get("requestContext") as
            | { orgSlug: string }
            | undefined
          return ctx.success(c, { email: "test@example.com" })
        })
      },
    })

    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      context: (req) => ({
        orgSlug: req.headers.get("x-org-slug") || "default-org",
      }),
      // Use dynamic providers (function)
      providers: async (c) => {
        return {
          dummy: createContextAwareProvider(),
        }
      },
      success: async (ctx, value) => {
        successContext = value.context as { orgSlug: string }
        return ctx.subject("user", { userID: value.email })
      },
    })

    // Start auth flow
    const authorizeResponse = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      {
        headers: { "x-org-slug": "dynamic-org" },
      },
    )
    const cookies = authorizeResponse.headers.get("set-cookie")

    // Follow redirect to provider - this goes through the dynamic route handler
    await auth.request("https://auth.example.com/dummy/authorize", {
      headers: {
        Cookie: cookies || "",
        "x-org-slug": "dynamic-org",
      },
    })

    // Context should be available in the provider's route handler
    expect(providerContextInRoute).toStrictEqual({ orgSlug: "dynamic-org" })
    // And in the success callback
    expect(successContext).toStrictEqual({ orgSlug: "dynamic-org" })
  })

  test("undefined context (default) maintains backward compatibility", async () => {
    let receivedValue: any

    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        receivedValue = value
        return ctx.subject("user", { userID: value.email })
      },
    })

    const authorizeResponse = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    const cookies = authorizeResponse.headers.get("set-cookie")

    await auth.request("https://auth.example.com/dummy/authorize", {
      headers: { Cookie: cookies || "" },
    })

    // context should be undefined when not configured
    expect(receivedValue.context).toBeUndefined()
    expect(receivedValue.provider).toBe("dummy")
  })
})

describe("dynamic basePath", () => {
  beforeEach(async () => {
    setSystemTime(new Date("1/1/2024"))
  })

  afterEach(() => {
    setSystemTime()
  })

  test("static string basePath works", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      basePath: "/auth/v1",
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(302)
    // Redirect should include basePath
    expect(response.headers.get("location")).toBe("/auth/v1/dummy/authorize")
  })

  test("dynamic function basePath works", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      basePath: (req) => `/auth/${req.headers.get("x-org-slug") || "default"}`,
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      {
        headers: {
          "x-org-slug": "acme",
        },
      },
    )
    expect(response.status).toBe(302)
    // Redirect should include dynamic basePath
    expect(response.headers.get("location")).toBe("/auth/acme/dummy/authorize")
  })

  test("metadata endpoints include basePath in URLs", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      basePath: "/auth/tenant1",
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/.well-known/oauth-authorization-server",
    )
    expect(response.status).toBe(200)
    const metadata = await response.json()

    expect(metadata.issuer).toBe("https://auth.example.com/auth/tenant1")
    expect(metadata.authorization_endpoint).toBe(
      "https://auth.example.com/auth/tenant1/authorize",
    )
    expect(metadata.token_endpoint).toBe(
      "https://auth.example.com/auth/tenant1/token",
    )
  })

  test("empty basePath (default) maintains current behavior", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: {
        dummy: createDummyProvider("test@example.com"),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(302)
    // Redirect should NOT have basePath prefix
    expect(response.headers.get("location")).toBe("/dummy/authorize")
  })

  test("tenant routes include basePath", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      basePath: "/auth/v2",
      providers: async (c) => ({
        dummy: createDummyProvider(
          `${(c.get("tenantId") as string) || "unknown"}@test.com`,
        ),
      }),
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.email })
      },
    })

    const response = await auth.request(
      "https://auth.example.com/tenant/acme/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(response.status).toBe(302)
    // Redirect should include both basePath and tenant
    expect(response.headers.get("location")).toBe(
      "/auth/v2/tenant/acme/dummy/authorize",
    )
  })
})
