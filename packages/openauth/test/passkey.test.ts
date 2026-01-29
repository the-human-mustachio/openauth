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
import { PasskeyProvider } from "../src/provider/passkey.js"
import { PasskeyUI } from "../src/ui/passkey.js"

const subjects = createSubjects({
  user: object({
    userID: string(),
  }),
})

describe("passkey provider UI", () => {
  beforeEach(async () => {
    setSystemTime(new Date("1/1/2024"))
  })

  afterEach(() => {
    setSystemTime()
  })

  test("authorize UI uses relative URLs for fetch calls", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: {
        passkey: PasskeyProvider(
          PasskeyUI({
            rpName: "Test App",
          }),
        ),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.userId })
      },
    })

    // First, initiate the OAuth flow to set up authorization cookie
    const authorizeResponse = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(authorizeResponse.status).toBe(302)
    const cookies = authorizeResponse.headers.get("set-cookie") || ""

    // Now request the passkey authorize page
    const response = await auth.request(
      "https://auth.example.com/passkey/authorize",
      { headers: { cookie: cookies } },
    )
    expect(response.status).toBe(200)

    const html = await response.text()

    // Verify fetch calls use relative URLs (no leading slash with /passkey/)
    expect(html).toContain('fetch(\n      "authenticate-options?')
    expect(html).toContain('fetch(\n      "authenticate-verify?')

    // Verify NO absolute paths are used
    expect(html).not.toContain('"/passkey/authenticate-options')
    expect(html).not.toContain('"/passkey/authenticate-verify')
  })

  test("register UI uses relative URLs for fetch calls", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: {
        passkey: PasskeyProvider(
          PasskeyUI({
            rpName: "Test App",
          }),
        ),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.userId })
      },
    })

    // First, initiate the OAuth flow to set up authorization cookie
    const authorizeResponse = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(authorizeResponse.status).toBe(302)
    const cookies = authorizeResponse.headers.get("set-cookie") || ""

    // Now request the passkey register page
    const response = await auth.request(
      "https://auth.example.com/passkey/register",
      { headers: { cookie: cookies } },
    )
    expect(response.status).toBe(200)

    const html = await response.text()

    // Verify fetch calls use relative URLs (no leading slash with /passkey/)
    expect(html).toContain('fetch(\n      "register-request?')
    expect(html).toContain('fetch(\n        "register-verify?')

    // Verify NO absolute paths are used
    expect(html).not.toContain('"/passkey/register-request')
    expect(html).not.toContain('"/passkey/register-verify')
  })

  test("passkey UI works with basePath - authorize", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      basePath: "/auth/acme",
      providers: {
        passkey: PasskeyProvider(
          PasskeyUI({
            rpName: "Test App",
          }),
        ),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.userId })
      },
    })

    // First, initiate the OAuth flow with basePath
    const authorizeResponse = await auth.request(
      "https://auth.example.com/auth/acme/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(authorizeResponse.status).toBe(302)
    // Redirect should include basePath
    expect(authorizeResponse.headers.get("location")).toBe(
      "/auth/acme/passkey/authorize",
    )

    const cookies = authorizeResponse.headers.get("set-cookie") || ""

    // Request passkey authorize page with basePath
    const response = await auth.request(
      "https://auth.example.com/auth/acme/passkey/authorize",
      { headers: { cookie: cookies } },
    )
    expect(response.status).toBe(200)

    const html = await response.text()

    // Verify relative URLs are used - these will resolve correctly
    // from /auth/acme/passkey/authorize to /auth/acme/passkey/authenticate-options
    expect(html).toContain('fetch(\n      "authenticate-options?')
    expect(html).not.toContain('"/passkey/authenticate-options')
  })

  test("passkey UI works with dynamic basePath", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      basePath: (req) => `/auth/${req.headers.get("x-org-slug") || "default"}`,
      providers: {
        passkey: PasskeyProvider(
          PasskeyUI({
            rpName: "Test App",
          }),
        ),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.userId })
      },
    })

    // First, initiate the OAuth flow with dynamic basePath
    const authorizeResponse = await auth.request(
      "https://auth.example.com/auth/myorg/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
      {
        headers: {
          "x-org-slug": "myorg",
        },
      },
    )
    expect(authorizeResponse.status).toBe(302)
    // Redirect should include dynamic basePath
    expect(authorizeResponse.headers.get("location")).toBe(
      "/auth/myorg/passkey/authorize",
    )

    const cookies = authorizeResponse.headers.get("set-cookie") || ""

    // Request passkey authorize page with dynamic basePath
    const response = await auth.request(
      "https://auth.example.com/auth/myorg/passkey/authorize",
      {
        headers: {
          cookie: cookies,
          "x-org-slug": "myorg",
        },
      },
    )
    expect(response.status).toBe(200)

    const html = await response.text()

    // Verify relative URLs are used
    expect(html).toContain('fetch(\n      "authenticate-options?')
    expect(html).not.toContain('"/passkey/authenticate-options')
  })

  test("passkey provider with custom name uses relative URLs correctly", async () => {
    const auth = issuer({
      storage: MemoryStorage(),
      subjects,
      allow: async () => true,
      providers: {
        // Using a custom name instead of "passkey"
        webauthn: PasskeyProvider(
          PasskeyUI({
            rpName: "Test App",
          }),
        ),
      },
      success: async (ctx, value) => {
        return ctx.subject("user", { userID: value.userId })
      },
    })

    // First, initiate the OAuth flow
    const authorizeResponse = await auth.request(
      "https://auth.example.com/authorize?client_id=123&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code",
    )
    expect(authorizeResponse.status).toBe(302)
    // Should redirect to custom provider name
    expect(authorizeResponse.headers.get("location")).toBe(
      "/webauthn/authorize",
    )

    const cookies = authorizeResponse.headers.get("set-cookie") || ""

    // Request the authorize page with custom provider name
    const response = await auth.request(
      "https://auth.example.com/webauthn/authorize",
      { headers: { cookie: cookies } },
    )
    expect(response.status).toBe(200)

    const html = await response.text()

    // Relative URLs will correctly resolve to /webauthn/authenticate-options
    // because they're relative to /webauthn/authorize
    expect(html).toContain('fetch(\n      "authenticate-options?')
    expect(html).not.toContain('"/passkey/')
    expect(html).not.toContain('"/webauthn/')
  })
})
