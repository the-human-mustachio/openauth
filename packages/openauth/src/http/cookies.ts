/**
 * Cookie parsing + serialization for the HTTP layer.
 *
 * The framework owns cookie policy (per `ARCHITECTURE.md` §"Response
 * sanitization"). Methods never set cookies through `Response.headers`; they
 * return `SetCookie[]` data and this module renders them. We additionally
 * strip method-returned `Set-Cookie` / security / `Cache-Control` headers so
 * methods cannot bypass policy.
 */
import type { CachePolicy, SetCookie } from "../types/method"

/** Parse an incoming `Cookie:` header into a read-only map. */
export function parseCookieHeader(header: string | null): Map<string, string> {
  const out = new Map<string, string>()
  if (!header) return out
  for (const part of header.split(";")) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const eq = trimmed.indexOf("=")
    if (eq === -1) {
      out.set(trimmed, "")
      continue
    }
    const name = trimmed.slice(0, eq).trim()
    const raw = trimmed.slice(eq + 1).trim()
    const value =
      raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw
    try {
      out.set(name, decodeURIComponent(value))
    } catch {
      out.set(name, value)
    }
  }
  return out
}

export type CookieDefaults = {
  /** Secure flag default. Production should pass `true`. */
  secure?: boolean
  domain?: string
  path?: string
}

const RESERVED_PREFIX = /^(auth|idp)\./

/**
 * Characters explicitly forbidden in a cookie name. RFC 6265 §4.1.1 defers
 * to RFC 2616's `token` grammar (no separators, no CTLs); rather than the
 * full grammar we reject the chars most likely to corrupt the header on
 * splice: `=`, `;`, `,`, and any whitespace. Method-returned cookie names
 * are the realistic source of bad input here — internal callers use fixed
 * `auth.*` / `idp.*` names that pass.
 */
const INVALID_COOKIE_NAME = /[=;,\s]/

function assertValidCookieName(name: string): void {
  if (!name || INVALID_COOKIE_NAME.test(name)) {
    throw new TypeError(
      `invalid cookie name ${JSON.stringify(name)} — must be non-empty and contain no '=', ';', ',' or whitespace`,
    )
  }
}

/**
 * Serialize a single `SetCookie` data instruction into a `Set-Cookie` header
 * string. Enforces framework policy:
 *   - `Secure` forced on if `defaults.secure === true`.
 *   - `SameSite` defaults to `Lax` if unspecified.
 *   - `HttpOnly` defaults to `true` for any cookie name in the `auth.*` /
 *     `idp.*` reserved namespace.
 *   - `null` value → `Max-Age=0` to clear.
 */
export function serializeSetCookie(
  cookie: SetCookie,
  defaults: CookieDefaults = {},
): string {
  assertValidCookieName(cookie.name)
  const parts: string[] = []
  const value = cookie.value ?? ""
  parts.push(`${cookie.name}=${encodeURIComponent(value)}`)

  const path = cookie.path ?? defaults.path ?? "/"
  parts.push(`Path=${path}`)

  const domain = cookie.domain ?? defaults.domain
  if (domain) parts.push(`Domain=${domain}`)

  if (cookie.value === null) {
    parts.push("Max-Age=0")
  } else if (cookie.maxAge !== undefined) {
    parts.push(`Max-Age=${cookie.maxAge}`)
  }

  const secure = cookie.secure ?? defaults.secure ?? false
  if (secure) parts.push("Secure")

  const httpOnly = cookie.httpOnly ?? RESERVED_PREFIX.test(cookie.name)
  if (httpOnly) parts.push("HttpOnly")

  const sameSite = cookie.sameSite ?? "lax"
  parts.push(`SameSite=${sameSite.charAt(0).toUpperCase() + sameSite.slice(1)}`)

  return parts.join("; ")
}

/** Headers the framework strips from any method-returned `Response`. */
const STRIPPED_HEADERS = [
  "set-cookie",
  "set-cookie2",
  "strict-transport-security",
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cache-control",
] as const

/**
 * Serialize a `MethodResult.challenge`'s `CachePolicy` into a
 * `Cache-Control` header value. The framework owns this header (methods
 * cannot set it directly — see `STRIPPED_HEADERS`); a method opts into
 * caching via the typed `cache` field and this renders it. Absent /
 * `maxAge: 0` ⇒ `no-store` (the safe default for auth UI).
 */
export function cacheControlHeader(cache: CachePolicy | undefined): string {
  if (!cache) return "no-store"
  if ((cache.maxAge ?? -1) === 0) return "no-store"
  const parts: string[] = []
  if (cache.isPrivate) parts.push("private")
  if (cache.maxAge !== undefined) parts.push(`max-age=${cache.maxAge}`)
  if (cache.sMaxAge !== undefined) parts.push(`s-maxage=${cache.sMaxAge}`)
  if (cache.immutable) parts.push("immutable")
  return parts.length ? parts.join(", ") : "no-store"
}

export type ApplyOptions = {
  setCookies?: SetCookie[]
  cookieDefaults?: CookieDefaults
  /** When set, framework writes this `Cache-Control` value. Default `no-store`. */
  cacheControl?: string
}

/**
 * Sanitize a method-returned `Response` and apply framework-owned headers.
 *
 * Returns a new `Response` so the original is left untouched. When the
 * method's response carried any of the stripped headers, emit a
 * `console.warn` so a programmer notices their header got dropped
 * silently. (Per ARCHITECTURE.md §"Response sanitization"; switches to
 * the Logger port when that lands in Phase 8.)
 */
export function applyResponsePolicy(
  response: Response,
  opts: ApplyOptions = {},
): Response {
  const headers = new Headers(response.headers)
  const stripped: string[] = []
  for (const h of STRIPPED_HEADERS) {
    if (headers.has(h)) {
      stripped.push(h)
      headers.delete(h)
    }
  }
  if (stripped.length > 0) {
    console.warn(
      `[openauth] dropped method-returned header(s) ${stripped.join(", ")} — the framework owns cookie/security/cache headers; methods should return cookies via MethodResult.setCookies.`,
    )
  }

  headers.set("Cache-Control", opts.cacheControl ?? "no-store")

  if (opts.setCookies) {
    for (const c of opts.setCookies) {
      headers.append("Set-Cookie", serializeSetCookie(c, opts.cookieDefaults))
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}
