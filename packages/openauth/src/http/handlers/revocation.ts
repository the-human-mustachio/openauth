/**
 * RFC 7009 `/revoke` and RFC 7662 `/introspect` HTTP shims.
 *
 * Both accept `application/x-www-form-urlencoded`. The current
 * implementation does not enforce client authentication beyond the
 * domain's own checks — confidential-client authentication on these
 * endpoints lands with the broader Phase 8 hardening pass.
 */
import { introspect } from "../../domain/introspect"
import { revokeToken } from "../../domain/revoke"
import { authError } from "../../types/error"
import { isErr } from "../../types/result"

import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"
import { introspectBodySchema, revokeBodySchema } from "../schemas/revocation"

export function makeRevokeHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const body = await readForm(c.req.raw)
    if (!body) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("body must be application/x-www-form-urlencoded"),
      )
    }
    const parsed = revokeBodySchema.safeParse(Object.fromEntries(body.entries()))
    if (!parsed.success) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(parsed.error.issues[0]?.message ?? "invalid"),
      )
    }
    const res = await revokeToken(
      {
        token: parsed.data.token,
        ...(parsed.data.token_type_hint
          ? { tokenTypeHint: parsed.data.token_type_hint }
          : {}),
      },
      {
        tokenStore: deps.tokenStore,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        clock: deps.clock,
      },
    )
    if (isErr(res)) return tokenEndpointErrorResponse(res.error)
    // RFC 7009 §2.2: success returns 200 with empty body.
    return new Response(null, {
      status: 200,
      headers: { "cache-control": "no-store" },
    })
  }
}

export function makeIntrospectHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const body = await readForm(c.req.raw)
    if (!body) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("body must be application/x-www-form-urlencoded"),
      )
    }
    const parsed = introspectBodySchema.safeParse(
      Object.fromEntries(body.entries()),
    )
    if (!parsed.success) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(parsed.error.issues[0]?.message ?? "invalid"),
      )
    }
    const res = await introspect(parsed.data.token, {
      keyStore: deps.keyStore,
      issuerUrl: c.get("issuerUrl"),
    })
    if (isErr(res)) return tokenEndpointErrorResponse(res.error)
    return new Response(JSON.stringify(res.value), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    })
  }
}

async function readForm(req: Request): Promise<URLSearchParams | null> {
  const ct = req.headers.get("content-type") ?? ""
  if (!ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return null
  }
  return new URLSearchParams(await req.text())
}
