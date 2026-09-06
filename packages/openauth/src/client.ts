/**
 * Use the OpenAuth client kick off your OAuth flows, exchange tokens, refresh tokens,
 * and verify tokens.
 *
 * First, create a client.
 *
 * ```ts title="client.ts"
 * import { createClient } from "@openauthjs/openauth/client"
 *
 * const client = createClient({
 *   clientID: "my-client",
 *   issuer: "https://auth.myserver.com"
 * })
 * ```
 *
 * Kick off the OAuth flow by calling `authorize`.
 *
 * ```ts
 * const redirect_uri = "https://myserver.com/callback"
 *
 * const { url } = await client.authorize(
 *   redirect_uri,
 *   "code"
 * )
 * ```
 *
 * When the user completes the flow, `exchange` the code for tokens.
 *
 * ```ts
 * const tokens = await client.exchange(query.get("code"), redirect_uri)
 * ```
 *
 * And `verify` the tokens.
 *
 * ```ts
 * const verified = await client.verify(subjects, tokens.access)
 * ```
 *
 * @packageDocumentation
 */
import {
  createLocalJWKSet,
  errors,
  JSONWebKeySet,
  jwtVerify,
  decodeJwt,
} from "jose"
import type { SubjectSchema } from "./types/subject"
import type { v1 } from "@standard-schema/spec"
import {
  InvalidAccessTokenError,
  InvalidAuthorizationCodeError,
  InvalidRefreshTokenError,
  InvalidSubjectError,
} from "./error.js"
import { generatePKCE } from "./pkce.js"

/**
 * The well-known information for an OAuth 2.0 authorization server.
 * @internal
 */
export interface WellKnown {
  /**
   * The URI to the JWKS endpoint.
   */
  jwks_uri: string
  /**
   * The URI to the token endpoint.
   */
  token_endpoint: string
  /**
   * The URI to the authorization endpoint.
   */
  authorization_endpoint: string
}

/**
 * The tokens returned by the auth server.
 */
export interface Tokens {
  /**
   * The access token.
   */
  access: string
  /**
   * The refresh token.
   */
  refresh: string

  /**
   * The number of seconds until the access token expires.
   */
  expiresIn: number

  /**
   * The OIDC `id_token` (signed JWT), present when `scope=openid` was granted.
   *
   * Refresh-grant rotation reissues this with a stable `auth_time` per
   * OIDC Core §12 and deliberately omits the original `nonce`.
   */
  idToken?: string
}

interface ResponseLike {
  json(): Promise<unknown>
  ok: Response["ok"]
}
type FetchLike = (...args: any[]) => Promise<ResponseLike>

/**
 * The challenge that you can use to verify the code.
 */
export type Challenge = {
  /**
   * The state that was sent to the redirect URI.
   */
  state: string
  /**
   * The verifier that was sent to the redirect URI.
   */
  verifier?: string
}

/**
 * Configure the client.
 */
export interface ClientInput {
  /**
   * The client ID. This is just a string to identify your app.
   *
   * If you have a web app and a mobile app, you want to use different client IDs both.
   *
   * @example
   * ```ts
   * {
   *   clientID: "my-client"
   * }
   * ```
   */
  clientID: string
  /**
   * The URL of your OpenAuth server.
   *
   * @example
   * ```ts
   * {
   *   issuer: "https://auth.myserver.com"
   * }
   * ```
   */
  issuer?: string
  /**
   * The client secret, for **confidential** clients only.
   *
   * Supply this for a server-side app registered as a confidential client;
   * `exchange()` and `refresh()` then authenticate at `/token`. Omit it for
   * public clients (SPA, mobile, CLI) — a secret cannot be kept in code
   * that ships to users, and the IdP requires PKCE there instead.
   *
   * Without this, a confidential client's `exchange()` is rejected with
   * `invalid_client`: the token endpoint has no way to authenticate it.
   *
   * @example
   * ```ts
   * {
   *   clientID: "my-server-app",
   *   clientSecret: process.env.CLIENT_SECRET
   * }
   * ```
   */
  clientSecret?: string
  /**
   * How to present `clientSecret` at the token endpoint.
   *
   * `client_secret_basic` (the default) sends HTTP Basic credentials, which
   * is what RFC 6749 §2.3.1 prefers and what the IdP parses first.
   * `client_secret_post` puts them in the form body. Both are advertised in
   * discovery as `token_endpoint_auth_methods_supported`.
   *
   * @default "client_secret_basic"
   */
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post"
  /**
   * Optionally, override the internally used fetch function.
   *
   * This is useful if you are using a polyfilled fetch function in your application and you
   * want the client to use it too.
   */
  fetch?: FetchLike
}

export interface AuthorizeOptions {
  /**
   * The provider you want to use for the OAuth flow.
   *
   * ```ts
   * {
   *   provider: "google"
   * }
   * ```
   *
   * If no provider is specified, the user is directed to a page where they can select from the
   * list of configured providers.
   *
   * If there's only one provider configured, the user will be redirected to that.
   */
  provider?: string
  /**
   * OAuth scopes to request, e.g. `["openid", "email", "profile"]`.
   *
   * Pass `openid` to request an `id_token` at `/token` (OIDC Core §2). Pass
   * `email` / `profile` / `phone` / `address` to opt into the standard §5.4
   * profile claim sets on the id_token and `/userinfo` response.
   *
   * Accepts an array or a pre-joined space-separated string. When omitted,
   * no `scope` is sent — the IdP's default grant applies, which typically
   * does NOT include `openid` and therefore does NOT issue an id_token.
   */
  scope?: string | string[]
}

export interface AuthorizeResult {
  /**
   * The challenge that you can use to verify the code. This is for the PKCE flow for SPA apps.
   *
   * This is an object that you _stringify_ and store it in session storage.
   *
   * ```ts
   * sessionStorage.setItem("challenge", JSON.stringify(challenge))
   * ```
   */
  challenge: Challenge
  /**
   * The URL to redirect the user to. This starts the OAuth flow.
   *
   * For example, for SPA apps.
   *
   * ```ts
   * location.href = url
   * ```
   */
  url: string
}

/**
 * Returned when the exchange is successful.
 */
export interface ExchangeSuccess {
  /**
   * This is always `false` when the exchange is successful.
   */
  err: false
  /**
   * The access and refresh tokens.
   */
  tokens: Tokens
}

/**
 * Returned when the exchange fails.
 */
export interface ExchangeError {
  /**
   * The type of error that occurred. You can handle this by checking the type.
   *
   * @example
   * ```ts
   * import { InvalidAuthorizationCodeError } from "@openauthjs/openauth/error"
   *
   * console.log(err instanceof InvalidAuthorizationCodeError)
   *```
   */
  err: InvalidAuthorizationCodeError
}

export interface RefreshOptions {
  /**
   * Optionally, pass in the access token.
   */
  access?: string
}

/**
 * Returned when the refresh is successful.
 */
export interface RefreshSuccess {
  /**
   * This is always `false` when the refresh is successful.
   */
  err: false
  /**
   * Returns the refreshed tokens only if they've been refreshed.
   *
   * If they are still valid, this will be `undefined`.
   */
  tokens?: Tokens
}

/**
 * Returned when the refresh fails.
 */
export interface RefreshError {
  /**
   * The type of error that occurred. You can handle this by checking the type.
   *
   * @example
   * ```ts
   * import { InvalidRefreshTokenError } from "@openauthjs/openauth/error"
   *
   * console.log(err instanceof InvalidRefreshTokenError)
   *```
   */
  err: InvalidRefreshTokenError | InvalidAccessTokenError
}

export interface VerifyOptions {
  /**
   * Optionally, pass in the refresh token.
   *
   * If passed in, this will automatically refresh the access token if it has expired.
   */
  refresh?: string
  /**
   * @internal
   */
  issuer?: string
  /**
   * The audience to require on the token.
   *
   * Defaults to this client's `clientID`, which is what the IdP puts in
   * `aud` for an ordinary login. Set this when verifying a token minted
   * for a **resource** — an `/authorize` call that passed `audience` puts
   * that value in `aud` instead, so a resource server verifying it must
   * name itself here.
   */
  audience?: string
  /**
   * Optionally, override the internally used fetch function.
   *
   * This is useful if you are using a polyfilled fetch function in your application and you
   * want the client to use it too.
   */
  fetch?: FetchLike
}

export interface VerifyResult<T extends SubjectSchema> {
  /**
   * This is always `false` when the verify is successful.
   *
   * A literal, not an optional — `err?: undefined` would leave the
   * property present on this arm, so `"err" in result` narrowed nothing
   * and callers had to test truthiness instead. Matches `ExchangeSuccess`
   * and `RefreshSuccess`.
   */
  err: false
  /**
   * Returns the refreshed tokens only if they’ve been refreshed.
   *
   * If they are still valid, this will be undefined.
   */
  tokens?: Tokens
  /**
   * @internal
   */
  aud: string
  /**
   * The decoded subjects from the access token.
   *
   * Has the same shape as the subjects you defined when creating the issuer.
   */
  subject: {
    [type in keyof T]: { type: type; properties: v1.InferOutput<T[type]> }
  }[keyof T]
}

/**
 * Returned when the verify call fails.
 */
export interface VerifyError {
  /**
   * The type of error that occurred. You can handle this by checking the type.
   *
   * @example
   * ```ts
   * import { InvalidRefreshTokenError } from "@openauthjs/openauth/error"
   *
   * console.log(err instanceof InvalidRefreshTokenError)
   *```
   */
  err: InvalidRefreshTokenError | InvalidAccessTokenError
}

/**
 * An instance of the OpenAuth client contains the following methods.
 */
export interface Client {
  /**
   * Start the authorization code flow.
   *
   * ```ts
   * const { challenge, url } = await client.authorize(<redirect_uri>)
   * // store `challenge`, then redirect the user to `url`
   * ```
   *
   * Returns the URL to send the user to, and a `challenge` carrying the
   * CSRF `state` and the PKCE `verifier`. Persist the challenge (a cookie
   * server-side, `sessionStorage` in a SPA) and hand the verifier back to
   * {@link Client.exchange} when the user returns.
   *
   * **PKCE is always used.** The IdP requires it for public clients, and
   * OAuth 2.1 §7.5.1 recommends it for confidential ones too, so there is
   * no reason to offer it as a toggle. Before 0.14.0 it was opt-in and
   * off by default, which meant the documented server-side flow could not
   * complete against a public client at all.
   *
   * Only the authorization code flow is supported. The implicit flow
   * (`response_type=token`) is removed in OAuth 2.1 and the IdP rejects
   * it with `unsupported_response_type`.
   */
  authorize(
    redirectURI: string,
    opts?: AuthorizeOptions,
  ): Promise<AuthorizeResult>
  /**
   * Exchange the code for access and refresh tokens.
   *
   * ```ts
   * const exchanged = await client.exchange(<code>, <redirect_uri>)
   * ```
   *
   * You call this after the user has been redirected back to your app after the OAuth flow.
   *
   * :::tip
   * For SSR sites, the code is returned in the query parameter.
   * :::
   *
   * So the code comes from the query parameter in the redirect URI. The redirect URI here is
   * the one that you passed in to the `authorize` call when starting the flow.
   *
   * :::tip
   * For SPA sites, the code is returned through the URL hash.
   * :::
   *
   * If you used the PKCE flow for an SPA app, the code is returned as a part of the redirect URL
   * hash.
   *
   * ```ts {4}
   * const exchanged = await client.exchange(
   *   <code>,
   *   <redirect_uri>,
   *   <challenge.verifier>
   * )
   * ```
   *
   * You also need to pass in the previously stored challenge verifier.
   *
   * This method returns the access and refresh tokens. Or if it fails, it returns an error that
   * you can handle depending on the error.
   *
   * ```ts
   * import { InvalidAuthorizationCodeError } from "@openauthjs/openauth/error"
   *
   * if (exchanged.err) {
   *   if (exchanged.err instanceof InvalidAuthorizationCodeError) {
   *     // handle invalid code error
   *   }
   *   else {
   *     // handle other errors
   *   }
   * }
   *
   * const { access, refresh } = exchanged.tokens
   * ```
   */
  exchange(
    code: string,
    redirectURI: string,
    verifier?: string,
  ): Promise<ExchangeSuccess | ExchangeError>
  /**
   * Refreshes the tokens if they have expired. This is used in an SPA app to maintain the
   * session, without logging the user out.
   *
   * ```ts
   * const next = await client.refresh(<refresh_token>)
   * ```
   *
   * Can optionally take the access token as well. If passed in, this will skip the refresh
   * if the access token is still valid.
   *
   * ```ts
   * const next = await client.refresh(<refresh_token>, { access: <access_token> })
   * ```
   *
   * This returns the refreshed tokens only if they've been refreshed.
   *
   * ```ts
   * if (!next.err) {
   *   // tokens are still valid
   * }
   * if (next.tokens) {
   *   const { access, refresh } = next.tokens
   * }
   * ```
   *
   * Or if it fails, it returns an error that you can handle depending on the error.
   *
   * ```ts
   * import { InvalidRefreshTokenError } from "@openauthjs/openauth/error"
   *
   * if (next.err) {
   *   if (next.err instanceof InvalidRefreshTokenError) {
   *     // handle invalid refresh token error
   *   }
   *   else {
   *     // handle other errors
   *   }
   * }
   * ```
   */
  refresh(
    refresh: string,
    opts?: RefreshOptions,
  ): Promise<RefreshSuccess | RefreshError>
  /**
   * Verify the token in the incoming request.
   *
   * This is typically used for SSR sites where the token is stored in an HTTP only cookie. And
   * is passed to the server on every request.
   *
   * ```ts
   * const verified = await client.verify(<subjects>, <token>)
   * ```
   *
   * This takes the subjects that you had previously defined when creating the issuer.
   *
   * :::tip
   * If the refresh token is passed in, it'll automatically refresh the access token.
   * :::
   *
   * This can optionally take the refresh token as well. If passed in, it'll automatically
   * refresh the access token if it has expired.
   *
   * ```ts
   * const verified = await client.verify(<subjects>, <token>, { refresh: <refresh_token> })
   * ```
   *
   * This returns the decoded subjects from the access token. And the tokens if they've been
   * refreshed.
   *
   * ```ts
   * // based on the subjects you defined earlier
   * console.log(verified.subject.properties.userID)
   *
   * if (verified.tokens) {
   *   const { access, refresh } = verified.tokens
   * }
   * ```
   *
   * Or if it fails, it returns an error that you can handle depending on the error.
   *
   * ```ts
   * import { InvalidRefreshTokenError } from "@openauthjs/openauth/error"
   *
   * if (verified.err) {
   *   if (verified.err instanceof InvalidRefreshTokenError) {
   *     // handle invalid refresh token error
   *   }
   *   else {
   *     // handle other errors
   *   }
   * }
   * ```
   */
  verify<T extends SubjectSchema>(
    subjects: T,
    token: string,
    options?: VerifyOptions,
  ): Promise<VerifyResult<T> | VerifyError>
}

/**
 * Create an OpenAuth client.
 *
 * @param input - Configure the client.
 */
export function createClient(input: ClientInput): Client {
  const jwksCache = new Map<string, ReturnType<typeof createLocalJWKSet>>()
  const issuerCache = new Map<string, WellKnown>()
  const issuer = input.issuer || process.env.OPENAUTH_ISSUER
  if (!issuer) throw new Error("No issuer")
  const f = input.fetch ?? fetch

  async function getIssuer() {
    const cached = issuerCache.get(issuer!)
    if (cached) return cached
    const wellKnown = (await (f || fetch)(
      `${issuer}/.well-known/oauth-authorization-server`,
    ).then((r) => r.json())) as WellKnown
    issuerCache.set(issuer!, wellKnown)
    return wellKnown
  }

  async function getJWKS() {
    const wk = await getIssuer()
    const cached = jwksCache.get(issuer!)
    if (cached) return cached
    const keyset = (await (f || fetch)(wk.jwks_uri).then((r) =>
      r.json(),
    )) as JSONWebKeySet
    const result = createLocalJWKSet(keyset)
    jwksCache.set(issuer!, result)
    return result
  }

  /**
   * Client authentication for the token endpoint (RFC 6749 §2.3.1).
   * Applied only when a `clientSecret` is configured; public clients
   * authenticate with PKCE instead and send neither.
   */
  function applyClientAuth(
    headers: Record<string, string>,
    body: URLSearchParams,
  ) {
    const secret = input.clientSecret
    if (secret === undefined) return
    if (
      (input.tokenEndpointAuthMethod ?? "client_secret_basic") ===
      "client_secret_post"
    ) {
      body.set("client_secret", secret)
      return
    }
    // §2.3.1 requires form-urlencoding each half before base64.
    const cred = `${encodeURIComponent(input.clientID)}:${encodeURIComponent(secret)}`
    headers["authorization"] = `Basic ${btoa(cred)}`
  }

  const result = {
    async authorize(redirectURI: string, opts?: AuthorizeOptions) {
      const wk = await getIssuer()
      const url = new URL(wk.authorization_endpoint)
      // PKCE unconditionally: required by the IdP for public clients, and
      // recommended for confidential ones by OAuth 2.1 §7.5.1.
      const pkce = await generatePKCE()
      const challenge: Challenge = {
        state: crypto.randomUUID(),
        verifier: pkce.verifier,
      }
      url.searchParams.set("client_id", input.clientID)
      url.searchParams.set("redirect_uri", redirectURI)
      url.searchParams.set("response_type", "code")
      url.searchParams.set("state", challenge.state)
      url.searchParams.set("code_challenge_method", "S256")
      url.searchParams.set("code_challenge", pkce.challenge)
      if (opts?.provider) url.searchParams.set("provider", opts.provider)
      if (opts?.scope !== undefined) {
        const scope = Array.isArray(opts.scope)
          ? opts.scope.join(" ")
          : opts.scope
        if (scope) url.searchParams.set("scope", scope)
      }
      return { challenge, url: url.toString() }
    },
    async exchange(
      code: string,
      redirectURI: string,
      verifier?: string,
    ): Promise<ExchangeSuccess | ExchangeError> {
      const wk = await getIssuer()
      const body = new URLSearchParams({
        code,
        redirect_uri: redirectURI,
        grant_type: "authorization_code",
        client_id: input.clientID,
      })
      if (verifier) body.set("code_verifier", verifier)
      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
      }
      applyClientAuth(headers, body)
      const tokens = await f(wk.token_endpoint, {
        method: "POST",
        headers,
        body: body.toString(),
      })
      const json = (await tokens.json()) as any
      if (!tokens.ok) {
        return {
          err: new InvalidAuthorizationCodeError(),
        }
      }
      return {
        err: false,
        tokens: {
          access: json.access_token as string,
          refresh: json.refresh_token as string,
          expiresIn: json.expires_in as number,
          ...(typeof json.id_token === "string"
            ? { idToken: json.id_token as string }
            : {}),
        },
      }
    },
    async refresh(
      refresh: string,
      opts?: RefreshOptions,
    ): Promise<RefreshSuccess | RefreshError> {
      if (opts && opts.access) {
        const decoded = decodeJwt(opts.access)
        if (!decoded) {
          return {
            err: new InvalidAccessTokenError(),
          }
        }
        // allow 30s window for expiration
        if ((decoded.exp || 0) > Date.now() / 1000 + 30) {
          return {
            err: false,
          }
        }
      }
      const wk = await getIssuer()
      // `client_id` was previously omitted here too. The IdP rejects a
      // confidential client's refresh outright when the request carries no
      // client identity (RFC 6749 §6), so rotation was unreachable for
      // exactly the clients that most need it.
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refresh,
        client_id: input.clientID,
      })
      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
      }
      applyClientAuth(headers, body)
      const tokens = await f(wk.token_endpoint, {
        method: "POST",
        headers,
        body: body.toString(),
      })
      const json = (await tokens.json()) as any
      if (!tokens.ok) {
        return {
          err: new InvalidRefreshTokenError(),
        }
      }
      return {
        err: false,
        tokens: {
          access: json.access_token as string,
          refresh: json.refresh_token as string,
          expiresIn: json.expires_in as number,
          ...(typeof json.id_token === "string"
            ? { idToken: json.id_token as string }
            : {}),
        },
      }
    },
    async verify<T extends SubjectSchema>(
      subjects: T,
      token: string,
      options?: VerifyOptions,
    ): Promise<VerifyResult<T> | VerifyError> {
      const jwks = await getJWKS()
      try {
        // RFC 9068 §4 / RFC 7519 §4.1.3 — `aud` MUST be checked. Until
        // 0.14.0 only `iss` was, so any client sharing an issuer accepted
        // any other client's token: a confused deputy across every RP on
        // the deployment.
        //
        // The IdP sets `aud` to the requested `audience` when one was
        // asked for at /authorize, and to the client id otherwise — so a
        // resource server verifying a resource-scoped token passes its own
        // identifier via `options.audience`, and everyone else gets the
        // right default for free.
        const result = await jwtVerify<{
          claim?: {
            type: keyof T
            properties: v1.InferInput<T[keyof T]>
          }
        }>(token, jwks, {
          issuer,
          audience: options?.audience ?? input.clientID,
        })
        const claim = result.payload.claim
        if (!claim || typeof claim.type !== "string") {
          return { err: new InvalidSubjectError() }
        }
        const subjectType = claim.type
        const schema = subjects[subjectType]
        if (!schema) {
          return { err: new InvalidSubjectError() }
        }
        const validated = await schema["~standard"].validate(claim.properties)
        if (validated.issues) {
          return { err: new InvalidSubjectError() }
        }
        return {
          err: false,
          aud: result.payload.aud as string,
          subject: {
            type: subjectType,
            properties: validated.value,
          } as any,
        }
      } catch (e) {
        if (e instanceof errors.JWTExpired && options?.refresh) {
          const refreshed = await this.refresh(options.refresh)
          if (refreshed.err) return refreshed
          const verified = await result.verify(
            subjects,
            refreshed.tokens!.access,
            {
              refresh: refreshed.tokens!.refresh,
              issuer,
              fetch: options?.fetch,
            },
          )
          if (verified.err) return verified
          verified.tokens = refreshed.tokens
          return verified
        }
        return {
          err: new InvalidAccessTokenError(),
        }
      }
    },
  }
  return result
}
