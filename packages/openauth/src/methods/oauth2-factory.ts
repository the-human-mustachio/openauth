/**
 * `oauth2Factory` and `oidcFactory` — generic multi-tenant factories.
 *
 * Use these when each tenant brings its own OAuth 2.0 / OIDC issuer,
 * client credentials, scopes, and endpoint URLs. The factory's
 * `configSchema` accepts a per-tenant blob and `build()` delegates to
 * `buildOauth2Method` / `buildOidcMethod` to produce the actual
 * `AuthMethod`.
 *
 * For built-in vendor wrappers (Google, GitHub, Apple, etc.) see
 * `./providers/*` — those bake in the issuer URL and provider quirks.
 *
 * For single-tenant deployments where the issuer / endpoints are
 * compile-time constants, you can still call `buildOauth2Method` /
 * `buildOidcMethod` directly inside your own `AuthMethodFactory` —
 * those entry points are the underlying "build a static AuthMethod"
 * primitives; this file just wraps them in the multi-tenant factory
 * shape.
 */
import { z } from "zod"

import { buildOauth2Method } from "./oauth2-generic"
import { buildOidcMethod } from "./oidc-generic"
import type {
  Oauth2Properties,
  Oauth2State,
} from "./oauth2-generic"
import type { AuthMethod, AuthMethodFactory } from "../types/method"

const oauth2ConfigSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
  scopes: z.array(z.string()).min(1),
  authorizationUrl: z.string().url(),
  tokenUrl: z.string().url(),
  jwksUri: z.string().url().optional(),
  expectedIssuer: z.string().optional(),
  extraAuthorizeParams: z.record(z.string()).optional(),
  pkce: z.enum(["S256", "none"]).optional(),
  responseMode: z.enum(["query", "form_post"]).optional(),
})

export type Oauth2FactoryConfig = z.infer<typeof oauth2ConfigSchema>

/**
 * Generic OAuth 2.0 factory.
 *
 * `kind: "oauth2"`. Use a different `MethodConfig.id` per instance to
 * register multiple OAuth 2.0 upstreams against a single tenant.
 */
export const oauth2Factory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  Oauth2FactoryConfig
> = {
  kind: "oauth2",
  configSchema: oauth2ConfigSchema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOauth2Method({
      id,
      kind,
      clientId: config.clientId,
      ...(config.clientSecret !== undefined
        ? { clientSecret: config.clientSecret }
        : {}),
      scopes: config.scopes,
      authorizationUrl: config.authorizationUrl,
      tokenUrl: config.tokenUrl,
      ...(config.jwksUri ? { jwksUri: config.jwksUri } : {}),
      ...(config.expectedIssuer
        ? { expectedIssuer: config.expectedIssuer }
        : {}),
      ...(config.extraAuthorizeParams
        ? { extraAuthorizeParams: config.extraAuthorizeParams }
        : {}),
      ...(config.pkce ? { pkce: config.pkce } : {}),
      ...(config.responseMode ? { responseMode: config.responseMode } : {}),
    }),
}

const oidcConfigSchema = z.object({
  issuer: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
  scopes: z.array(z.string()).optional(),
  extraAuthorizeParams: z.record(z.string()).optional(),
  pkce: z.enum(["S256", "none"]).optional(),
  responseMode: z.enum(["query", "form_post"]).optional(),
  /**
   * Skip discovery and use these endpoints directly. Useful for
   * providers with non-standard or fragmented discovery
   * (Microsoft tenant-templated, legacy stacks).
   */
  endpoints: z
    .object({
      authorization_endpoint: z.string().url(),
      token_endpoint: z.string().url(),
      jwks_uri: z.string().url(),
      issuer: z.string(),
    })
    .optional(),
})

export type OidcFactoryConfig = z.infer<typeof oidcConfigSchema>

/**
 * Generic OIDC factory. Auto-discovers `<issuer>/.well-known/openid-
 * configuration` unless `endpoints` is supplied.
 *
 * `kind: "oidc"`. Use a different `MethodConfig.id` per instance to
 * register multiple OIDC upstreams against a single tenant.
 */
export const oidcFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  OidcFactoryConfig
> = {
  kind: "oidc",
  configSchema: oidcConfigSchema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOidcMethod({
      id,
      kind,
      issuer: config.issuer,
      clientId: config.clientId,
      ...(config.clientSecret !== undefined
        ? { clientSecret: config.clientSecret }
        : {}),
      scopes: config.scopes ?? ["openid", "email", "profile"],
      ...(config.extraAuthorizeParams
        ? { extraAuthorizeParams: config.extraAuthorizeParams }
        : {}),
      ...(config.pkce ? { pkce: config.pkce } : {}),
      ...(config.responseMode ? { responseMode: config.responseMode } : {}),
      ...(config.endpoints
        ? {
            endpoints: {
              authorization_endpoint: config.endpoints.authorization_endpoint,
              token_endpoint: config.endpoints.token_endpoint,
              jwks_uri: config.endpoints.jwks_uri,
              issuer: config.endpoints.issuer,
            },
          }
        : {}),
    }),
}
