/**
 * `GET|POST /end_session` — OIDC RP-Initiated Logout 1.0 §2.
 *
 * Per spec, both GET (query) and POST (form body) are supported. The
 * tenant is resolved via the standard `tenantMiddleware`; the issuer URL
 * is taken from the per-request context.
 *
 * Outputs follow `domain/logout.ts`:
 *  - `redirect` → 302 to the validated `post_logout_redirect_uri` with
 *    `state` echoed when present.
 *  - `ok` → 200 with a minimal plain-text body. Hosts that need a styled
 *    "logged out" page can layer their own handler over `/end_session`.
 *  - errors → 400 with a JSON OAuth-style body (never 302; an unregistered
 *    `post_logout_redirect_uri` would otherwise be an open redirector).
 */
import { endSession } from "../../domain/logout"
import { authError } from "../../types/error"
import { isErr } from "../../types/result"

import { applyResponsePolicy } from "../cookies"
import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"
import { endSessionParamsSchema } from "../schemas/end-session"

export function makeEndSessionHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const tenant = c.get("tenant")
    if (!tenant) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("tenant unresolved"),
      )
    }

    // GET → query; POST → form body. Anything else → 400.
    let raw: Record<string, string>
    const httpMethod = c.req.method.toUpperCase()
    if (httpMethod === "GET") {
      raw = Object.fromEntries(new URL(c.req.url).searchParams.entries())
    } else if (httpMethod === "POST") {
      const ct = (c.req.header("content-type") ?? "").toLowerCase()
      if (!ct.startsWith("application/x-www-form-urlencoded")) {
        return tokenEndpointErrorResponse(
          authError.invalidRequest(
            "POST /end_session requires application/x-www-form-urlencoded body",
          ),
        )
      }
      raw = Object.fromEntries(new URLSearchParams(await c.req.raw.text()))
    } else {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(`unsupported method "${httpMethod}"`),
      )
    }

    const parsed = endSessionParamsSchema.safeParse(raw)
    if (!parsed.success) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(
          parsed.error.issues[0]?.message ?? "invalid request",
        ),
      )
    }
    const q = parsed.data

    const res = await endSession(
      {
        ...(q.id_token_hint !== undefined
          ? { idTokenHint: q.id_token_hint }
          : {}),
        ...(q.client_id !== undefined ? { clientId: q.client_id } : {}),
        ...(q.post_logout_redirect_uri !== undefined
          ? { postLogoutRedirectUri: q.post_logout_redirect_uri }
          : {}),
        ...(q.state !== undefined ? { state: q.state } : {}),
      },
      tenant,
      {
        configStore: deps.configStore,
        tokenStore: deps.tokenStore,
        keyStore: deps.keyStore,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        issuerUrl: c.get("issuerUrl"),
        clock: deps.clock,
      },
    )

    if (isErr(res)) return tokenEndpointErrorResponse(res.error)

    if (res.value.kind === "redirect") {
      return applyResponsePolicy(
        new Response(null, {
          status: 302,
          headers: { location: res.value.url },
        }),
        { setCookies: [], cookieDefaults: deps.cookieDefaults },
      )
    }
    return new Response("Logged out.", {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    })
  }
}
