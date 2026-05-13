/**
 * `POST /par` — Pushed Authorization Requests (RFC 9126 §2).
 *
 * Body: `application/x-www-form-urlencoded` carrying the same parameter
 * set the RP would otherwise put on `GET /authorize`, plus `client_id`
 * and optionally `client_secret`. Client credentials may alternatively
 * ride in `Authorization: Basic` (RFC 6749 §2.3.1).
 *
 * Response: HTTP 201, JSON `{request_uri, expires_in}` on success.
 */
import { resolveClientCredentials } from "../../domain/client-auth"
import { pushAuthorizationRequest } from "../../domain/par"
import { authError } from "../../types/error"
import { isErr } from "../../types/result"

import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"
import { parBodySchema } from "../schemas/par"

export function makeParHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const tenant = c.get("tenant")
    if (!tenant) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("tenant unresolved"),
      )
    }
    const ct = (c.req.header("content-type") ?? "").toLowerCase()
    if (!ct.startsWith("application/x-www-form-urlencoded")) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(
          "body must be application/x-www-form-urlencoded",
        ),
      )
    }
    const raw = Object.fromEntries(
      new URLSearchParams(await c.req.raw.text()).entries(),
    )
    const parsed = parBodySchema.safeParse(raw)
    if (!parsed.success) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(
          parsed.error.issues[0]?.message ?? "invalid request",
        ),
      )
    }
    const creds = resolveClientCredentials({
      authorizationHeader: c.req.header("authorization") ?? null,
      bodyClientId: parsed.data.client_id,
      bodyClientSecret: parsed.data.client_secret,
    })
    const clientId = creds?.clientId ?? parsed.data.client_id

    // Strip auth-only fields from the param record we persist — they
    // belong to `/par`, not to the rehydrated `/authorize` request.
    const { client_secret: _strip, ...paramsForAuthorize } = parsed.data
    void _strip

    const res = await pushAuthorizationRequest(
      {
        clientId,
        ...(creds?.clientSecret !== undefined
          ? { clientSecret: creds.clientSecret }
          : {}),
        params: paramsForAuthorize,
      },
      tenant,
      {
        configStore: deps.configStore,
        sessionStore: deps.sessionStore,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        clock: deps.clock,
      },
    )
    if (isErr(res)) return tokenEndpointErrorResponse(res.error)
    return new Response(JSON.stringify(res.value), {
      status: 201,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    })
  }
}
