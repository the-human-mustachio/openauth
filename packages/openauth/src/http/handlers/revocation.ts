/**
 * RFC 7009 `/revoke` and RFC 7662 `/introspect` HTTP shims.
 *
 * Both accept `application/x-www-form-urlencoded`. Client credentials
 * may ride in the form body (`client_id`, `client_secret`) or in an
 * `Authorization: Basic` header (RFC 6749 §2.3.1); the header wins when
 * both are present.
 *
 * Revoke: anonymous calls are permitted for tokens issued to public
 * clients (RFC 7009 §2.1). Confidential-client tokens require auth.
 *
 * Introspect: client auth is REQUIRED (RFC 7662 §2.1). Anonymous calls
 * are rejected at this layer with `invalid_client`.
 */
import { resolveClientCredentials } from "../../domain/client-auth"
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
    const creds = resolveClientCredentials({
      authorizationHeader: c.req.header("authorization") ?? null,
      bodyClientId: parsed.data.client_id,
      bodyClientSecret: parsed.data.client_secret,
    })
    const res = await revokeToken(
      {
        token: parsed.data.token,
        ...(parsed.data.token_type_hint
          ? { tokenTypeHint: parsed.data.token_type_hint }
          : {}),
        ...(creds ? { clientId: creds.clientId } : {}),
        ...(creds?.clientSecret !== undefined
          ? { clientSecret: creds.clientSecret }
          : {}),
      },
      {
        tokenStore: deps.tokenStore,
        configStore: deps.configStore,
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
    const creds = resolveClientCredentials({
      authorizationHeader: c.req.header("authorization") ?? null,
      bodyClientId: parsed.data.client_id,
      bodyClientSecret: parsed.data.client_secret,
    })
    if (!creds) {
      // RFC 7662 §2.1 — endpoint MUST require some form of auth.
      return tokenEndpointErrorResponse(
        authError.invalidClient(
          "introspection requires client authentication",
        ),
      )
    }
    const res = await introspect(
      {
        token: parsed.data.token,
        ...(parsed.data.token_type_hint
          ? { tokenTypeHint: parsed.data.token_type_hint }
          : {}),
        clientId: creds.clientId,
        ...(creds.clientSecret !== undefined
          ? { clientSecret: creds.clientSecret }
          : {}),
      },
      {
        keyStore: deps.keyStore,
        configStore: deps.configStore,
        issuerUrl: c.get("issuerUrl"),
      },
    )
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
