/**
 * `GET|POST /m/:methodId/*` — the credential-flow dispatch endpoint.
 *
 * Methods that need POST routes (`password` `/login`, `code` `/send`+`/verify`,
 * `passkey` `/authenticate-options` etc.) declare them on
 * `AuthMethod.routes`. The HTTP layer mounts those routes here. The
 * `domain/method-route.handleMethodRoute` orchestrator handles flow lookup
 * + dispatch + result translation.
 */
import { handleMethodRoute } from "../../domain/method-route"
import { authError } from "../../types/error"
import { isErr } from "../../types/result"

import { applyResponsePolicy } from "../cookies"
import type { HttpContext, HttpDeps } from "../context"
import { authorizeDirectErrorResponse } from "../errors"

export function makeMethodRouteHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const tenant = c.get("tenant")
    if (!tenant) {
      return authorizeDirectErrorResponse(
        authError.invalidRequest("tenant unresolved"),
      )
    }
    const cookies = c.get("cookies")
    const flowId = cookies.get("idp.flow")
    if (!flowId) {
      return authorizeDirectErrorResponse(
        authError.invalidRequest("missing flow cookie", "flow"),
      )
    }

    // /m/<methodId>/<subPath>
    const url = new URL(c.req.url)
    const segments = url.pathname.split("/").filter(Boolean)
    if (segments.length < 3 || segments[0] !== "m") {
      return authorizeDirectErrorResponse(
        authError.invalidRequest("malformed method route", "path"),
      )
    }
    const methodId = segments[1]!
    const subPath = "/" + segments.slice(2).join("/")
    const httpMethod = c.req.method.toUpperCase() === "POST" ? "POST" : "GET"

    const result = await handleMethodRoute(
      {
        rawRequest: c.req.raw,
        tenant,
        methodId,
        subPath,
        httpMethod,
        flowId,
        cookies,
      },
      {
        sessionStore: deps.sessionStore,
        tokenStore: deps.tokenStore,
        keyStore: deps.keyStore,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        methodCache: deps.methodCache,
        clock: deps.clock,
      },
    )

    if (isErr(result)) return authorizeDirectErrorResponse(result.error)

    const out = result.value
    switch (out.kind) {
      case "issue-code": {
        const redirect = new URL(out.appRedirectUri)
        redirect.searchParams.set("code", out.code)
        if (out.appState !== null)
          redirect.searchParams.set("state", out.appState)
        return applyResponsePolicy(
          new Response(null, {
            status: 302,
            headers: { location: redirect.toString() },
          }),
          {
            setCookies: [clearFlowCookie()],
            cookieDefaults: deps.cookieDefaults,
          },
        )
      }
      case "challenge":
        return applyResponsePolicy(out.response, {
          setCookies: out.setCookies,
          cookieDefaults: deps.cookieDefaults,
        })
      case "denied":
        return applyResponsePolicy(
          new Response(`access_denied: ${out.reason}`, {
            status: 403,
            headers: { "content-type": "text/plain" },
          }),
          {
            setCookies: [clearFlowCookie(), ...out.setCookies],
            cookieDefaults: deps.cookieDefaults,
          },
        )
    }
  }
}

function clearFlowCookie() {
  return {
    name: "idp.flow",
    value: null,
    path: "/",
    httpOnly: true,
    sameSite: "lax" as const,
    maxAge: 0,
  }
}
