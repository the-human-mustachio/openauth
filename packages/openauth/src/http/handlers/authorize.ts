/**
 * `GET /authorize` handler.
 *
 * Parse + validate query → call `startAuthorize` → serialize the typed
 * `AuthorizeOutput` per OAuth 2.1 §4.1.2:
 *   - `challenge`           → method's response, sanitized + framework cookies.
 *   - `issue-code`          → 302 to `appRedirectUri` with `code` + `state`.
 *   - `denied`              → redirect with OAuth `access_denied`.
 *   - `select-method`       → host-supplied `renderPicker`, or the bundled
 *                             default in `ui/picker.ts`.
 *
 * Errors that occur **before** we have a verified RP redirect_uri (unknown
 * client, mismatched redirect, etc.) surface as plain-text 400 — never a
 * 302 — to avoid open-redirector behavior.
 */
import { isErr } from "../../types/result"
import { startAuthorize } from "../../domain/authorize"
import { asTenantId } from "../../types/tenant"
import { authError } from "../../types/error"
import type { AuthorizationRequest } from "../../types/authorization"
import type { PickerContext, PickerMethod } from "../../types/picker"
import { renderPicker as renderDefaultPicker } from "../../ui/picker"

import { applyResponsePolicy } from "../cookies"
import type { HttpContext, HttpDeps } from "../context"
import {
  authorizeDirectErrorResponse,
  authorizeRedirectErrorResponse,
  isNonRecoverable,
} from "../errors"
import {
  authorizeQuerySchema,
  authorizeRequestUriQuerySchema,
} from "../schemas/authorize"

export function makeAuthorizeHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const tenant = c.get("tenant")
    if (!tenant) {
      return authorizeDirectErrorResponse(
        authError.invalidRequest("tenant unresolved"),
      )
    }

    const url = new URL(c.req.url)
    const raw = Object.fromEntries(url.searchParams.entries())

    // RFC 9126 §4: rehydrate a PAR record when `request_uri` is present.
    // The user-agent URL carries only `client_id` + `request_uri`; the
    // stored params drive the rest of the request through the standard
    // parser below.
    let workingRaw: Record<string, string> = raw
    if (raw.request_uri !== undefined) {
      const parParsed = authorizeRequestUriQuerySchema.safeParse(raw)
      if (!parParsed.success) {
        return authorizeDirectErrorResponse(
          authError.invalidRequest(
            parParsed.error.issues[0]?.message ?? "invalid request",
            parParsed.error.issues[0]?.path[0]?.toString() ?? "request",
          ),
        )
      }
      if (!deps.sessionStore.consumePar) {
        return authorizeDirectErrorResponse(
          authError.invalidRequest(
            "session adapter does not support PAR",
            "request_uri",
          ),
        )
      }
      const par = await deps.sessionStore.consumePar(parParsed.data.request_uri)
      if (isErr(par)) {
        return authorizeDirectErrorResponse(
          authError.invalidRequest(
            "unknown or expired request_uri",
            "request_uri",
          ),
        )
      }
      if (par.value.clientId !== parParsed.data.client_id) {
        return authorizeDirectErrorResponse(
          authError.invalidRequest(
            "request_uri belongs to a different client",
            "request_uri",
          ),
        )
      }
      workingRaw = par.value.params
    }

    const parsed = authorizeQuerySchema.safeParse(workingRaw)
    if (!parsed.success) {
      const first = parsed.error.issues[0]
      const field = first?.path[0]?.toString() ?? "request"
      return authorizeDirectErrorResponse(
        authError.invalidRequest(first?.message ?? "invalid request", field),
      )
    }
    const q = parsed.data

    // RFC 9126 §2 per-client PAR enforcement: refuse direct `/authorize`
    // when the client requires PAR and `request_uri` was absent.
    if (raw.request_uri === undefined) {
      const client = tenant.config.clients.find((c) => c.id === q.client_id)
      if (client?.requirePushedAuthorizationRequests) {
        return authorizeDirectErrorResponse(
          authError.invalidRequest(
            "this client requires Pushed Authorization Requests (RFC 9126)",
            "request_uri",
          ),
        )
      }
    }

    if (q.response_type !== "code") {
      // OAuth 2.1: only `code` is supported. Implicit (`token`) is removed.
      return authorizeDirectErrorResponse({
        code: "invalid_request",
        description: `unsupported response_type "${q.response_type}" — OAuth 2.1 is code-only`,
        field: "response_type",
      })
    }

    const request: AuthorizationRequest = {
      tenantId: asTenantId(tenant.id),
      clientId: q.client_id,
      redirectUri: q.redirect_uri,
      responseType: "code",
      scopes: q.scope ?? [],
      state: q.state ?? null,
      ...(q.audience !== undefined ? { audience: q.audience } : {}),
      ...(q.method_id !== undefined ? { methodId: q.method_id } : {}),
      ...(q.code_challenge !== undefined
        ? { codeChallenge: q.code_challenge }
        : {}),
      ...(q.code_challenge_method !== undefined
        ? { codeChallengeMethod: q.code_challenge_method }
        : {}),
      ...(q.prompt !== undefined ? { prompt: q.prompt } : {}),
      ...(q.ui_locales !== undefined ? { uiLocales: q.ui_locales } : {}),
      ...(q.nonce !== undefined ? { nonce: q.nonce } : {}),
    }

    const result = await startAuthorize(
      {
        request,
        rawRequest: c.req.raw,
        tenant,
        cookies: c.get("cookies"),
      },
      {
        sessionStore: deps.sessionStore,
        tokenStore: deps.tokenStore,
        keyStore: deps.keyStore,
        methodCache: deps.methodCache,
        stateKeys: deps.stateKeys,
        issuerUrl: c.get("issuerUrl"),
        clock: deps.clock,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        ...(deps.callbackHostFor
          ? {
              callbackHostFor: (id: string) =>
                deps.callbackHostFor!(id as never),
            }
          : {}),
      },
    )

    if (isErr(result)) {
      const err = result.error
      if (isNonRecoverable(err)) {
        return authorizeDirectErrorResponse(err)
      }
      return authorizeRedirectErrorResponse(
        err,
        q.redirect_uri,
        q.state ?? null,
      )
    }

    const out = result.value
    switch (out.kind) {
      case "challenge": {
        // Framework stamps the `idp.flow` cookie so credential POSTs to
        // `/m/<methodId>/<sub>` can identify the in-flight flow.
        const flowCookie = {
          name: "idp.flow",
          value: out.flowId,
          path: "/",
          httpOnly: true,
          sameSite: "lax" as const,
          maxAge: 60 * 10,
        }
        return applyResponsePolicy(out.response, {
          setCookies: [flowCookie, ...out.setCookies],
          cookieDefaults: deps.cookieDefaults,
          cacheControl: cacheControlFor(out.cache),
        })
      }
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
      case "denied":
        return applyResponsePolicy(
          authorizeRedirectErrorResponse(
            { code: "access_denied", description: out.reason },
            q.redirect_uri,
            q.state ?? null,
          ),
          {
            setCookies: [clearFlowCookie(), ...out.setCookies],
            cookieDefaults: deps.cookieDefaults,
          },
        )
      case "select-method": {
        const pickerCtx: PickerContext = {
          clientId: q.client_id,
          redirectUri: q.redirect_uri,
          state: q.state ?? null,
          scope: q.scope ? q.scope.join(" ") : null,
          nonce: q.nonce ?? null,
          codeChallenge: q.code_challenge ?? null,
          codeChallengeMethod: q.code_challenge_method ?? null,
          audience: q.audience ?? null,
          prompt: q.prompt ? q.prompt.join(" ") : null,
          uiLocales: q.ui_locales ? q.ui_locales.join(" ") : null,
        }
        const methods: PickerMethod[] = out.methods.map((m) => ({
          id: m.id,
          kind: m.kind,
          type: m.type,
        }))
        const render = deps.renderPicker ?? renderDefaultPicker
        return await render(methods, pickerCtx)
      }
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

function cacheControlFor(
  cache:
    | {
        maxAge?: number
        sMaxAge?: number
        isPrivate?: boolean
        immutable?: boolean
      }
    | undefined,
): string {
  if (!cache) return "no-store"
  if ((cache.maxAge ?? -1) === 0) return "no-store"
  const parts: string[] = []
  if (cache.isPrivate) parts.push("private")
  if (cache.maxAge !== undefined) parts.push(`max-age=${cache.maxAge}`)
  if (cache.sMaxAge !== undefined) parts.push(`s-maxage=${cache.sMaxAge}`)
  if (cache.immutable) parts.push("immutable")
  return parts.length ? parts.join(", ") : "no-store"
}
