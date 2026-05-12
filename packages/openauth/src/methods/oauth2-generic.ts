/**
 * `buildOauth2Method` — the base OAuth 2.0 method that every redirect-style
 * provider wraps.
 *
 * Producers (the per-provider wrappers under `methods/providers/*`) call
 * this from their factory's `build` to construct a fully-formed
 * `AuthMethod`. The wrapper supplies endpoint URLs, scopes, any provider
 * quirks (Microsoft tenant template, Apple `form_post` mode, etc.). The
 * generic owns:
 *
 *   - `GET /authorize` — build the upstream redirect, mint optional PKCE,
 *     stash verifier/nonce in `methodState`, route through the
 *     framework's MAC-bound `state` envelope.
 *   - `GET /callback` (and `POST /callback` for `response_mode=form_post`)
 *     — exchange code at the token endpoint, optionally verify the
 *     `id_token` against a JWKS endpoint, return success with the
 *     standard `Oauth2Properties` payload.
 *
 * The framework writes `state` and verifies it on the callback; this
 * method only needs to thread `ctx.dispatch.state` through to the upstream.
 *
 * Where `oauth4webapi` helps (per AD7b): PKCE primitives, `id_token`
 * verification edge cases. The bulk of the OAuth dance is plain `fetch` +
 * URL building — providers diverge enough that ceremony round-trips
 * directly are clearer than packing into `oauth4webapi`'s strict
 * `AuthorizationServer` shape.
 */
import * as oauth from "oauth4webapi"
import { createRemoteJWKSet, jwtVerify } from "jose"

/**
 * Decoded id_token claims surfaced through the public API. Structurally
 * identical to `jose`'s `JWTPayload`, declared locally so consumers
 * never depend on this package's specific `jose` version. All claim
 * names are optional and weakly typed — runtime code should narrow with
 * `typeof claims.sub === "string"` style checks before use.
 */
type IdTokenClaims = Record<string, unknown>

import { authError } from "../types/error"
import type { AuthMethod, MethodContext, MethodResult } from "../types/method"
import type { MethodType } from "../types/tenant"

/** The payload every OAuth/OIDC method emits to the framework's `success` callback. */
export type Oauth2Properties = {
  tokens: {
    access: string
    refresh?: string
    expiresIn?: number
    /** Present when the upstream returned an id_token (OIDC providers, some OAuth ones). */
    idToken?: string
  }
  /** Claims decoded from the id_token if one was returned. */
  idTokenClaims?: IdTokenClaims
  /** Raw token-endpoint response. Surfaced for callers that need provider-specific fields. */
  raw: Record<string, unknown>
}

/** Method-private state carried on the FlowRecord through the round trip. */
export type Oauth2State = {
  /** PKCE verifier sent at /authorize; checked into the token-exchange body. */
  pkceVerifier?: string
}

export type Oauth2MethodInput = {
  /** From `AuthMethodFactory.build({ id })`. */
  id: string
  /** From `AuthMethodFactory.build({ kind })`. */
  kind: string
  /** `MethodType` advertised in `MethodConfig.type`. Defaults to `"oauth2"`. */
  type?: MethodType

  /** Upstream OAuth client id (per-tenant). */
  clientId: string
  /** Upstream OAuth client secret (per-tenant). Public clients omit. */
  clientSecret?: string
  /** Scopes to request. */
  scopes: string[]

  /** Upstream URLs. */
  authorizationUrl: string
  tokenUrl: string
  /** JWKS URI for id_token verification. OIDC providers set this. */
  jwksUri?: string
  /** Expected id_token issuer (used when `jwksUri` is set). */
  expectedIssuer?: string

  /** Provider-specific query parameters appended to `/authorize`. */
  extraAuthorizeParams?: Record<string, string>
  /**
   * PKCE mode. `"S256"` is the OAuth 2.1 default; `"none"` skips PKCE for
   * legacy upstreams that don't accept `code_challenge`.
   */
  pkce?: "S256" | "none"
  /**
   * `response_mode`. Apple requires `form_post` when requesting `name` /
   * `email` scopes; most providers leave this unset.
   */
  responseMode?: "query" | "form_post"
  /**
   * Hook to map the token response + id_token claims into a stable
   * provider subject id. Default: prefer `idTokenClaims.sub`, else
   * `raw.user_id` / `raw.id`. Providers that compute the id differently
   * (e.g. Discord stamps `id` on the userinfo) override here.
   */
  deriveSubject?: (input: {
    raw: Record<string, unknown>
    idTokenClaims?: IdTokenClaims
  }) => string
}

export async function buildOauth2Method(
  opts: Oauth2MethodInput,
): Promise<AuthMethod<Oauth2Properties, Oauth2State>> {
  const pkceMode = opts.pkce ?? "S256"
  const deriveSubject = opts.deriveSubject ?? defaultDeriveSubject
  const responseMode = opts.responseMode ?? "query"

  // Build once: the upstream JWKS resolver. Lazily fetched on first use.
  // jose's URL type comes from `node:url` in some toolchains; the cast is
  // safe — the WHATWG URL is a superset.
  const jwks = opts.jwksUri
    ? createRemoteJWKSet(new URL(opts.jwksUri) as never)
    : undefined

  return {
    id: opts.id,
    kind: opts.kind,
    type: opts.type ?? "oauth2",
    routes: {
      "GET /authorize": async (ctx) =>
        buildAuthorizeRedirect(ctx, opts, pkceMode),
      "GET /callback": async (ctx) =>
        exchangeAndSucceed(ctx, opts, jwks, deriveSubject),
      ...(responseMode === "form_post"
        ? {
            "POST /callback": async (ctx) =>
              exchangeAndSucceed(ctx, opts, jwks, deriveSubject),
          }
        : {}),
    },
  }
}

async function buildAuthorizeRedirect(
  ctx: MethodContext<Oauth2State>,
  opts: Oauth2MethodInput,
  pkceMode: "S256" | "none",
): Promise<MethodResult<Oauth2Properties, Oauth2State>> {
  if (!ctx.dispatch) {
    return {
      kind: "error",
      error: authError.internalError("dispatch missing on /authorize"),
    }
  }
  const url = new URL(opts.authorizationUrl)
  url.searchParams.set("client_id", opts.clientId)
  url.searchParams.set("redirect_uri", ctx.dispatch.callbackUrl)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("state", ctx.dispatch.state)
  url.searchParams.set("scope", opts.scopes.join(" "))
  if (opts.responseMode === "form_post") {
    url.searchParams.set("response_mode", "form_post")
  }
  for (const [k, v] of Object.entries(opts.extraAuthorizeParams ?? {})) {
    url.searchParams.set(k, v)
  }

  let saveMethodState: Oauth2State | undefined
  if (pkceMode === "S256") {
    const verifier = oauth.generateRandomCodeVerifier()
    const challenge = await oauth.calculatePKCECodeChallenge(verifier)
    url.searchParams.set("code_challenge", challenge)
    url.searchParams.set("code_challenge_method", "S256")
    saveMethodState = { pkceVerifier: verifier }
  }

  return {
    kind: "challenge",
    response: new Response(null, {
      status: 302,
      headers: { location: url.toString() },
    }),
    ...(saveMethodState ? { saveMethodState } : {}),
  }
}

async function exchangeAndSucceed(
  ctx: MethodContext<Oauth2State>,
  opts: Oauth2MethodInput,
  jwks: ReturnType<typeof createRemoteJWKSet> | undefined,
  deriveSubject: NonNullable<Oauth2MethodInput["deriveSubject"]>,
): Promise<MethodResult<Oauth2Properties, Oauth2State>> {
  // Pull the auth code from query (GET callback) or form body (form_post).
  const { code, error } = await readCallbackParams(ctx.request)
  if (error) {
    return {
      kind: "error",
      error: authError.accessDenied(error),
    }
  }
  if (!code) {
    return {
      kind: "error",
      error: authError.invalidRequest("missing authorization code", "code"),
    }
  }

  if (!ctx.flow) {
    return {
      kind: "error",
      error: authError.internalError("flow missing on callback"),
    }
  }
  const callbackUrl = `${new URL(ctx.request.url).protocol}//${ctx.flow.callbackHost}${ctx.flow.callbackPath}`

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: callbackUrl,
    client_id: opts.clientId,
  })
  if (opts.clientSecret) body.set("client_secret", opts.clientSecret)
  const verifier = ctx.methodState?.pkceVerifier
  if (verifier) body.set("code_verifier", verifier)

  let tokenResponse: Record<string, unknown>
  try {
    const res = await fetch(opts.tokenUrl, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: body.toString(),
    })
    tokenResponse = (await res.json()) as Record<string, unknown>
  } catch (e) {
    return {
      kind: "error",
      error: authError.serverError("token endpoint fetch failed", e),
    }
  }
  if (typeof tokenResponse.error === "string") {
    return {
      kind: "error",
      error: authError.invalidGrant(
        `upstream error: ${tokenResponse.error}${
          typeof tokenResponse.error_description === "string"
            ? ` — ${tokenResponse.error_description}`
            : ""
        }`,
      ),
    }
  }

  const access = tokenResponse.access_token as string | undefined
  if (!access) {
    return {
      kind: "error",
      error: authError.invalidGrant("token response missing access_token"),
    }
  }
  const idToken = tokenResponse.id_token as string | undefined
  let idTokenClaims: IdTokenClaims | undefined
  if (idToken && jwks) {
    try {
      const { payload } = await jwtVerify(idToken, jwks, {
        audience: opts.clientId,
        ...(opts.expectedIssuer ? { issuer: opts.expectedIssuer } : {}),
      })
      // jose returns JWTPayload (a Record<string, unknown> in disguise);
      // widen to our locally-declared alias so the public surface stays
      // free of jose-specific types.
      idTokenClaims = payload as IdTokenClaims
    } catch (e) {
      return {
        kind: "error",
        error: authError.invalidGrant(
          `id_token verification failed: ${
            e instanceof Error ? e.message : "unknown"
          }`,
        ),
      }
    }
  }

  const properties: Oauth2Properties = {
    tokens: {
      access,
      ...(typeof tokenResponse.refresh_token === "string"
        ? { refresh: tokenResponse.refresh_token }
        : {}),
      ...(typeof tokenResponse.expires_in === "number"
        ? { expiresIn: tokenResponse.expires_in }
        : {}),
      ...(idToken ? { idToken } : {}),
    },
    ...(idTokenClaims ? { idTokenClaims } : {}),
    raw: tokenResponse,
  }

  const providerSubject = deriveSubject({
    raw: tokenResponse,
    ...(idTokenClaims ? { idTokenClaims } : {}),
  })
  if (!providerSubject) {
    return {
      kind: "error",
      error: authError.invalidGrant(
        "could not derive provider subject from upstream response",
      ),
    }
  }

  return {
    kind: "success",
    providerSubject,
    properties,
  }
}

async function readCallbackParams(
  req: Request,
): Promise<{ code: string | null; error: string | null }> {
  if (req.method === "POST") {
    const ct = req.headers.get("content-type") ?? ""
    if (ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(await req.clone().text())
      return {
        code: params.get("code"),
        error: params.get("error_description") ?? params.get("error") ?? null,
      }
    }
  }
  const url = new URL(req.url)
  return {
    code: url.searchParams.get("code"),
    error:
      url.searchParams.get("error_description") ??
      url.searchParams.get("error") ??
      null,
  }
}

function defaultDeriveSubject(input: {
  raw: Record<string, unknown>
  idTokenClaims?: IdTokenClaims
}): string {
  if (input.idTokenClaims && typeof input.idTokenClaims.sub === "string") {
    return input.idTokenClaims.sub
  }
  const raw = input.raw
  for (const k of ["sub", "user_id", "id"]) {
    const v = raw[k]
    if (typeof v === "string") return v
    if (typeof v === "number") return v.toString()
  }
  return ""
}
