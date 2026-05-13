/**
 * Public metadata handlers.
 *
 *   GET /.well-known/openid-configuration
 *   GET /.well-known/oauth-authorization-server  (alias of the OIDC doc)
 *   GET /.well-known/jwks.json
 *
 * Discovery is cacheable; JWKS is cacheable with a short TTL (the framework
 * rotates signing keys monthly per cross-cutting decisions). We advertise
 * `Cache-Control: public, max-age=60` on both — clients can re-fetch on
 * `kid` miss.
 */
import { buildDiscoveryDocument, buildJwks } from "../../domain/discovery"
import { isErr } from "../../types/result"

import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"

export function makeDiscoveryHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const doc = buildDiscoveryDocument({
      issuerUrl: c.get("issuerUrl"),
      ...(deps.customScopeClaims !== undefined
        ? { customScopeClaims: deps.customScopeClaims }
        : {}),
    })
    return new Response(JSON.stringify(doc), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=60",
      },
    })
  }
}

export function makeJwksHandler(deps: HttpDeps) {
  return async (_c: HttpContext): Promise<Response> => {
    const res = await buildJwks(deps.keyStore)
    if (isErr(res)) return tokenEndpointErrorResponse(res.error)
    return new Response(JSON.stringify(res.value), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=60",
      },
    })
  }
}
