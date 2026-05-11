/**
 * `GET /cb/:methodId` handler — upstream-provider callback.
 *
 * The tenant middleware has already run the recovery chain; `c.get("recovery")`
 * carries the outcome. The handler delegates to `handleCallback` which
 * performs the state-flow consistency check, dispatches the method's `GET
 * /callback`, and either mints the auth code or returns an interstitial
 * challenge.
 */
import { handleCallback } from "../../domain/callback"
import { isErr } from "../../types/result"

import { applyResponsePolicy } from "../cookies"
import type { HttpContext, HttpDeps } from "../context"
import { authorizeDirectErrorResponse } from "../errors"

export function makeCallbackHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const result = await handleCallback(
      { rawRequest: c.req.raw, cookies: c.get("cookies") },
      {
        configStore: deps.configStore,
        sessionStore: deps.sessionStore,
        tokenStore: deps.tokenStore,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        methodCache: deps.methodCache,
        stateKeys: deps.stateKeys,
        clock: deps.clock,
      },
    )

    if (isErr(result)) {
      // The callback URL does not carry an RP redirect URI — surface plain
      // text and let the operator inspect logs / audit for context.
      return authorizeDirectErrorResponse(result.error)
    }

    const out = result.value
    switch (out.kind) {
      case "issue-code": {
        const redirect = new URL(out.appRedirectUri)
        redirect.searchParams.set("code", out.code)
        if (out.appState !== null)
          redirect.searchParams.set("state", out.appState)
        return new Response(null, {
          status: 302,
          headers: {
            location: redirect.toString(),
            "cache-control": "no-store",
          },
        })
      }
      case "challenge":
        return applyResponsePolicy(out.response, {
          setCookies: out.setCookies,
          cookieDefaults: deps.cookieDefaults,
          cacheControl: out.cache
            ? out.cache.maxAge === 0
              ? "no-store"
              : "no-store"
            : "no-store",
        })
      case "denied":
        return applyResponsePolicy(
          new Response(`access_denied: ${out.reason}`, {
            status: 403,
            headers: { "content-type": "text/plain" },
          }),
          { setCookies: out.setCookies, cookieDefaults: deps.cookieDefaults },
        )
    }
  }
}
