/**
 * `buildOidcMethod` — OIDC layer over `buildOauth2Method`.
 *
 * Fetches `/.well-known/openid-configuration` from the configured issuer
 * once per factory build (the result is cached for the lifetime of the
 * `MethodCache` entry, which expires with the tenant config). Plumbs the
 * discovered authorization / token / jwks endpoints into the underlying
 * OAuth 2.0 method and turns on id_token verification.
 *
 * Providers that don't ship a discovery doc (or have a non-standard one)
 * can pass `endpoints` directly to bypass discovery and still get id_token
 * validation. This is how Microsoft works — the discovery doc lives at
 * `/<tenant>/v2.0/.well-known/openid-configuration`, and the user picks
 * which tenant template to use.
 */
import { buildOauth2Method } from "./oauth2-generic"
import type {
  Oauth2MethodInput,
  Oauth2Properties,
  Oauth2State,
} from "./oauth2-generic"
import { authError, type AuthError } from "../types/error"
import type { AuthMethod } from "../types/method"

type Endpoints = {
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  issuer: string
}

export type OidcMethodInput = Omit<
  Oauth2MethodInput,
  "authorizationUrl" | "tokenUrl" | "jwksUri" | "expectedIssuer" | "type"
> & {
  /** Issuer URL — the framework appends `/.well-known/openid-configuration`. */
  issuer: string
  /**
   * Skip discovery and use these endpoints directly. Useful for providers
   * with non-standard or fragmented discovery (Microsoft tenant-templated,
   * legacy stacks).
   */
  endpoints?: Endpoints
}

/**
 * Async — the factory's `build()` awaits discovery if `endpoints` is not
 * provided. Result is cached inside `MethodCache` until the tenant config
 * is invalidated.
 */
export async function buildOidcMethod(
  opts: OidcMethodInput,
): Promise<AuthMethod<Oauth2Properties, Oauth2State>> {
  const endpoints = opts.endpoints ?? (await fetchDiscovery(opts.issuer))
  const scopes = opts.scopes.includes("openid")
    ? opts.scopes
    : ["openid", ...opts.scopes]
  return buildOauth2Method({
    ...opts,
    type: "oidc",
    scopes,
    authorizationUrl: endpoints.authorization_endpoint,
    tokenUrl: endpoints.token_endpoint,
    jwksUri: endpoints.jwks_uri,
    expectedIssuer: endpoints.issuer,
  })
}

async function fetchDiscovery(issuer: string): Promise<Endpoints> {
  const url = issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration"
  let json: Record<string, unknown>
  try {
    const res = await fetch(url)
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`)
    }
    json = (await res.json()) as Record<string, unknown>
  } catch (e) {
    throw oidcConfigError(
      `failed to fetch OIDC discovery from ${url}: ${
        e instanceof Error ? e.message : "unknown"
      }`,
    )
  }
  for (const k of [
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "issuer",
  ] as const) {
    if (typeof json[k] !== "string") {
      throw oidcConfigError(
        `OIDC discovery doc missing "${k}" (issuer=${issuer})`,
      )
    }
  }
  return {
    authorization_endpoint: json.authorization_endpoint as string,
    token_endpoint: json.token_endpoint as string,
    jwks_uri: json.jwks_uri as string,
    issuer: json.issuer as string,
  }
}

function oidcConfigError(description: string): Error & { cause: AuthError } {
  const err = new Error(description) as Error & { cause: AuthError }
  err.cause = authError.serverError(description)
  return err
}
