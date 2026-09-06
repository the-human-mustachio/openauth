/**
 * `GET|POST /m/:methodId/*` — the credential-flow dispatch endpoint.
 *
 * Methods that need POST routes (`password` `/login`, `code` `/send`+`/verify`,
 * `passkey` `/authenticate-options` etc.) declare them on
 * `AuthMethod.routes`. The HTTP layer mounts those routes here. The
 * `domain/method-route.handleMethodRoute` orchestrator handles flow lookup
 * + dispatch + result translation.
 */
import {
  handleMethodRoute,
  handlePublicMethodRoute,
} from "../../domain/method-route"
import type { RouteKey } from "../../domain/method-dispatch"
import { callbackTarget } from "../../domain/mount"
import { authError } from "../../types/error"
import { isErr } from "../../types/result"

import { applyResponsePolicy, cacheControlHeader } from "../cookies"
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

    // Public fast-path (additive — leaves the cookie-gated path below
    // byte-identical for every non-public request). Only a clean hit —
    // well-formed `/m/<id>/<sub>`, method resolves, and the resolved
    // method explicitly lists this route key in `publicRoutes` — is
    // diverted here, cookie-free. Anything else falls through to the
    // original flow-cookie-gated logic with its original error
    // ordering. `methodCache.resolve` is a cache lookup; the duplicate
    // resolve on the gated path is a cache hit.
    {
      const u = new URL(c.req.url)
      const segs = u.pathname.split("/").filter(Boolean)
      if (segs.length >= 3 && segs[0] === "m") {
        const methodId = segs[1]!
        const subPath = "/" + segs.slice(2).join("/")
        const httpMethod =
          c.req.method.toUpperCase() === "POST" ? "POST" : "GET"
        const routeKey = `${httpMethod} ${subPath}` as RouteKey
        const resolved = await deps.methodCache.resolve(tenant.config, methodId)
        if (
          !isErr(resolved) &&
          resolved.value.publicRoutes?.includes(routeKey)
        ) {
          const issuerUrl = c.get("issuerUrl")
          // Same derivation as domain/authorize.ts — both call
          // `callbackTarget`, which is the single source of truth. The
          // metadata.test.ts anti-drift test asserts the emitted
          // entityID/ACS equal what buildAuthnRequestRedirect derives.
          const { url: callbackUrl } = callbackTarget({
            issuerUrl,
            methodId,
            callbackHost: deps.callbackHostFor?.(tenant.id),
          })
          const pub = await handlePublicMethodRoute(
            {
              rawRequest: c.req.raw,
              tenant,
              method: resolved.value,
              route: routeKey,
              subPath,
              dispatch: { state: "", callbackUrl, issuerUrl },
            },
            {
              sessionStore: deps.sessionStore,
              tokenStore: deps.tokenStore,
              clock: deps.clock,
              ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
              ...(deps.onLogout ? { onLogout: deps.onLogout } : {}),
            },
          )
          if (isErr(pub)) return authorizeDirectErrorResponse(pub.error)
          if (pub.value.kind === "denied") {
            return applyResponsePolicy(
              new Response(`access_denied: ${pub.value.reason}`, {
                status: 403,
                headers: { "content-type": "text/plain" },
              }),
              { cookieDefaults: deps.cookieDefaults },
            )
          }
          return applyResponsePolicy(pub.value.response, {
            cacheControl: cacheControlHeader(pub.value.cache),
            cookieDefaults: deps.cookieDefaults,
          })
        }
      }
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
        issuerUrl: c.get("issuerUrl"),
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
