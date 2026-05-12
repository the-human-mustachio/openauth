/**
 * OAuth / OIDC provider matrix test.
 *
 * One parameterized case per provider:
 *   1. Mock `fetch` so discovery + token endpoints return deterministic
 *      JSON. We do NOT issue id_tokens — the test exercises the wiring
 *      and claim mapping; full id_token verification needs a real signed
 *      JWT and matching JWKS, which is best left to integration tests
 *      against real upstreams.
 *   2. Drive `/authorize` and check the redirect lands on the expected
 *      upstream URL with the framework-minted `state` + the provider's
 *      configured scopes.
 *   3. Simulate the upstream callback (`/cb/<methodId>?state=...&code=upstream-code`)
 *      and check the IdP mints an auth code and redirects back to the RP.
 *   4. Exchange the auth code at `/token` and check tokens are issued.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test"

import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { s256Challenge } from "../../src/domain/pkce"
import * as providers from "../../src/methods/providers"
import { oauth2Factory, oidcFactory } from "../../src/methods/oauth2-factory"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"
import { ok } from "../../src/types/result"
import type { AnyAuthMethodFactory } from "../../src/types/method"

import { buildStateKeys } from "../helpers/state-keys"
import { authorizeUrl, tokenRequest } from "../helpers/idp"

type ProviderSpec = {
  name: string
  factory: AnyAuthMethodFactory
  config: Record<string, unknown>
  expectedAuthHostPrefix: string
  /**
   * For OIDC providers we mock the discovery doc; for OAuth2 / Cognito
   * we don't need to. Set when applicable.
   */
  discoveryHost?: string
  /** Endpoints reachable by the mock fetch for the token exchange. */
  tokenHost: string
}

const SPECS: ProviderSpec[] = [
  {
    name: "google",
    factory: providers.googleFactory as AnyAuthMethodFactory,
    config: { clientId: "g-id", clientSecret: "g-secret" },
    expectedAuthHostPrefix: "https://accounts.google.com",
    discoveryHost: "https://accounts.google.com",
    tokenHost: "https://oauth2.googleapis.com",
  },
  {
    name: "github",
    factory: providers.githubFactory as AnyAuthMethodFactory,
    config: { clientId: "gh-id", clientSecret: "gh-secret" },
    expectedAuthHostPrefix: "https://github.com",
    tokenHost: "https://github.com",
  },
  {
    name: "apple",
    factory: providers.appleFactory as AnyAuthMethodFactory,
    config: { clientId: "ap-id", clientSecret: "ap-secret" },
    expectedAuthHostPrefix: "https://appleid.apple.com",
    discoveryHost: "https://appleid.apple.com",
    tokenHost: "https://appleid.apple.com",
  },
  {
    name: "microsoft",
    factory: providers.microsoftFactory as AnyAuthMethodFactory,
    config: { clientId: "ms-id", clientSecret: "ms-secret" },
    expectedAuthHostPrefix: "https://login.microsoftonline.com",
    discoveryHost: "https://login.microsoftonline.com",
    tokenHost: "https://login.microsoftonline.com",
  },
  {
    name: "discord",
    factory: providers.discordFactory as AnyAuthMethodFactory,
    config: { clientId: "d-id", clientSecret: "d-secret" },
    expectedAuthHostPrefix: "https://discord.com",
    tokenHost: "https://discord.com",
  },
  {
    name: "facebook",
    factory: providers.facebookFactory as AnyAuthMethodFactory,
    config: { clientId: "fb-id", clientSecret: "fb-secret" },
    expectedAuthHostPrefix: "https://www.facebook.com",
    tokenHost: "https://graph.facebook.com",
  },
  {
    name: "linkedin",
    factory: providers.linkedinFactory as AnyAuthMethodFactory,
    config: { clientId: "li-id", clientSecret: "li-secret" },
    expectedAuthHostPrefix: "https://www.linkedin.com",
    tokenHost: "https://www.linkedin.com",
  },
  {
    name: "slack",
    factory: providers.slackFactory as AnyAuthMethodFactory,
    config: { clientId: "sl-id", clientSecret: "sl-secret" },
    expectedAuthHostPrefix: "https://slack.com",
    tokenHost: "https://slack.com",
  },
  {
    name: "spotify",
    factory: providers.spotifyFactory as AnyAuthMethodFactory,
    config: { clientId: "sp-id", clientSecret: "sp-secret" },
    expectedAuthHostPrefix: "https://accounts.spotify.com",
    tokenHost: "https://accounts.spotify.com",
  },
  {
    name: "twitch",
    factory: providers.twitchFactory as AnyAuthMethodFactory,
    config: { clientId: "tw-id", clientSecret: "tw-secret" },
    expectedAuthHostPrefix: "https://id.twitch.tv",
    tokenHost: "https://id.twitch.tv",
  },
  {
    name: "x",
    factory: providers.xFactory as AnyAuthMethodFactory,
    config: { clientId: "x-id", clientSecret: "x-secret" },
    expectedAuthHostPrefix: "https://twitter.com",
    tokenHost: "https://api.x.com",
  },
  {
    name: "yahoo",
    factory: providers.yahooFactory as AnyAuthMethodFactory,
    config: { clientId: "y-id", clientSecret: "y-secret" },
    expectedAuthHostPrefix: "https://api.login.yahoo.com",
    discoveryHost: "https://api.login.yahoo.com",
    tokenHost: "https://api.login.yahoo.com",
  },
  {
    name: "jumpcloud",
    factory: providers.jumpcloudFactory as AnyAuthMethodFactory,
    config: { clientId: "jc-id", clientSecret: "jc-secret" },
    expectedAuthHostPrefix: "https://oauth.id.jumpcloud.com",
    discoveryHost: "https://oauth.id.jumpcloud.com",
    tokenHost: "https://oauth.id.jumpcloud.com",
  },
  {
    name: "keycloak",
    factory: providers.keycloakFactory as AnyAuthMethodFactory,
    config: {
      clientId: "kc-id",
      clientSecret: "kc-secret",
      baseUrl: "https://kc.example",
      realm: "acme",
    },
    expectedAuthHostPrefix: "https://kc.example",
    discoveryHost: "https://kc.example",
    tokenHost: "https://kc.example",
  },
  {
    name: "cognito",
    factory: providers.cognitoFactory as AnyAuthMethodFactory,
    config: {
      clientId: "co-id",
      clientSecret: "co-secret",
      domain: "my-pool.auth.us-east-1.amazoncognito.com",
      issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xyz",
    },
    expectedAuthHostPrefix: "https://my-pool.auth.us-east-1.amazoncognito.com",
    tokenHost: "https://my-pool.auth.us-east-1.amazoncognito.com",
  },
  // Generic OAuth 2.0 factory — host points the tenant at an arbitrary
  // upstream by configuring the URLs directly.
  {
    name: "oauth2",
    factory: oauth2Factory as AnyAuthMethodFactory,
    config: {
      clientId: "gen-oauth2-id",
      clientSecret: "gen-oauth2-secret",
      scopes: ["read"],
      authorizationUrl: "https://upstream.example/authorize",
      tokenUrl: "https://upstream.example/token",
    },
    expectedAuthHostPrefix: "https://upstream.example",
    tokenHost: "https://upstream.example",
  },
  // Generic OIDC factory — auto-discovers from the issuer URL.
  {
    name: "oidc",
    factory: oidcFactory as AnyAuthMethodFactory,
    config: {
      clientId: "gen-oidc-id",
      clientSecret: "gen-oidc-secret",
      issuer: "https://upstream.example",
    },
    expectedAuthHostPrefix: "https://upstream.example",
    discoveryHost: "https://upstream.example",
    tokenHost: "https://upstream.example",
  },
]

const realFetch = globalThis.fetch

function installMockFetch() {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : "url" in input
          ? input.url
          : input.toString()
    if (url.includes("/.well-known/openid-configuration")) {
      const origin = new URL(url).origin
      const host = new URL(url).host
      // Microsoft discovery doc points to login.microsoftonline.com regardless of tenant.
      const issuer = host.startsWith("login.microsoftonline.com")
        ? new URL(url).pathname.replace("/.well-known/openid-configuration", "")
          ? `${origin}${new URL(url).pathname.replace("/.well-known/openid-configuration", "")}`
          : origin
        : origin
      return new Response(
        JSON.stringify({
          issuer,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          jwks_uri: `${origin}/jwks`,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )
    }
    if (
      url.endsWith("/jwks") ||
      url.endsWith("/keys") ||
      url.includes("jwks") ||
      url.includes("keys")
    ) {
      return new Response(JSON.stringify({ keys: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }
    // Token exchanges — match by method=POST + content-type.
    const method =
      typeof input !== "string" && "method" in input
        ? (input as Request).method
        : (init?.method ?? "GET")
    if (method.toUpperCase() === "POST") {
      return new Response(
        JSON.stringify({
          access_token: "mock-access",
          refresh_token: "mock-refresh",
          expires_in: 3600,
          token_type: "Bearer",
          sub: "upstream-user-1",
          id: "upstream-user-1",
          user_id: "upstream-user-1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )
    }
    return new Response("not mocked", { status: 404 })
  }) as typeof fetch
}

function restoreMockFetch() {
  globalThis.fetch = realFetch
}

beforeAll(installMockFetch)
afterAll(restoreMockFetch)

async function buildIdpFor(spec: ProviderSpec) {
  const tenant: TenantConfig = {
    id: asTenantId("acme"),
    displayName: "Acme",
    clients: [
      {
        id: "rp-1",
        name: "RP",
        type: "public",
        redirectUris: ["https://app.example/callback"],
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["openid"],
        pkceRequired: true,
      },
    ],
    methods: [
      {
        id: spec.name,
        kind: spec.factory.kind,
        type: "oauth2",
        enabled: true,
        config: spec.config,
      },
    ],
  }
  return createIdP({
    resolveTenant: async () => ok(tenant.id),
    stateKeys: buildStateKeys(),
    configStore: new MemoryConfigStore({ seed: [tenant] }),
    tokenStore: new MemoryTokenStore({
      keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
      clock: () => Date.now(),
    }),
    sessionStore: new MemorySessionStore({ clock: () => Date.now() }),
    keyStore: new MemoryKeyStore({ clock: () => Date.now() }),
    auditLog: new MemoryAuditLog(),
    issuerUrl: "https://idp.example",
    methods: { [spec.factory.kind]: spec.factory },
    subjects: {} as never,
    success: async ({ providerSubject, properties }) =>
      ({
        type: "user",
        properties: {
          id: providerSubject,
          ...(properties as object),
        },
      }) as never,
  })
}

describe("OAuth/OIDC provider matrix", () => {
  for (const spec of SPECS) {
    test(`${spec.name}: authorize → callback → token`, async () => {
      const idp = await buildIdpFor(spec)
      const verifier = "v".repeat(48)
      const challenge = await s256Challenge(verifier)

      // 1. /authorize → 302 to upstream.
      const authorize = await idp.handle(
        new Request(
          authorizeUrl("https://idp.example", {
            response_type: "code",
            client_id: "rp-1",
            redirect_uri: "https://app.example/callback",
            scope: "openid",
            state: "rp-csrf",
            code_challenge: challenge,
            code_challenge_method: "S256",
          }),
        ),
      )
      expect(authorize.status).toBe(302)
      const upstreamLoc = authorize.headers.get("location")!
      expect(upstreamLoc.startsWith(spec.expectedAuthHostPrefix)).toBe(true)
      const upstream = new URL(upstreamLoc)
      const state = upstream.searchParams.get("state")!
      expect(state).toBeString()
      expect(upstream.searchParams.get("client_id")).toBe(
        spec.config.clientId as string,
      )
      expect(upstream.searchParams.get("response_type")).toBe("code")

      // 2. Simulate upstream callback.
      const cb = await idp.handle(
        new Request(
          `https://idp.example/cb/${spec.name}?state=${encodeURIComponent(state)}&code=upstream-code`,
        ),
      )
      expect(cb.status).toBe(302)
      const cbLoc = new URL(cb.headers.get("location")!)
      expect(cbLoc.origin + cbLoc.pathname).toBe("https://app.example/callback")
      const authCode = cbLoc.searchParams.get("code")!
      expect(authCode).toBeString()
      expect(cbLoc.searchParams.get("state")).toBe("rp-csrf")

      // 3. /token.
      const tokenRes = await idp.handle(
        tokenRequest("https://idp.example", {
          grant_type: "authorization_code",
          code: authCode,
          client_id: "rp-1",
          redirect_uri: "https://app.example/callback",
          code_verifier: verifier,
        }),
      )
      expect(tokenRes.status).toBe(200)
      const body = await tokenRes.json()
      expect(body.access_token.split(".").length).toBe(3)
      expect(body.refresh_token).toBeString()
    })
  }
})
