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
    // issuer.ts maps internal errors to the error() handler.
    // If it happens during the initial authorize, it might result in UnknownStateError
    // because the auth state isn't established yet.
    expect(response.status).toBe(400)
    expect(await response.text()).toContain("The browser was in an unknown state")
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
