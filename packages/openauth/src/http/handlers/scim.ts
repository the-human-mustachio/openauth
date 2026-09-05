/**
 * `/scim/v2/*` — SCIM 2.0 provisioning.
 *
 * Thin by design: parse the request into plain data, hand it to
 * `handleScimRequest`, serialize the result. Every decision — auth,
 * routing, validation, status codes — lives in the domain, so the whole
 * SCIM surface is testable without Hono.
 *
 * Responses carry `application/scim+json` per RFC 7644 §3.1.
 */
import { handleScimRequest } from "../../domain/scim/handle"
import { scimErrorBody } from "../../domain/scim/resource"

import type { HttpContext, HttpDeps } from "../context"

const SCIM_CONTENT_TYPE = "application/scim+json;charset=utf-8"
const MOUNT = "/scim/v2"

function scimResponse(
  status: number,
  body: Record<string, unknown> | null,
  extra: Record<string, string> = {},
): Response {
  if (body === null || status === 204) {
    return new Response(null, { status, headers: extra })
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": SCIM_CONTENT_TYPE,
      // Provisioning responses are per-tenant and mutable; never cached.
      "cache-control": "no-store",
      ...extra,
    },
  })
}

export function makeScimHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    if (!deps.scimDirectory) {
      return scimResponse(
        501,
        scimErrorBody(
          501,
          "SCIM is not configured on this deployment (no scimDirectory " +
            "was supplied to createIdP)",
        ),
      )
    }

    const tenant = c.get("tenant")
    if (!tenant) {
      // The tenant middleware could not resolve a partition. Answer the
      // same way an unknown token does, so this endpoint never reveals
      // which tenants exist.
      return scimResponse(
        403,
        scimErrorBody(403, "SCIM provisioning is not enabled for this tenant"),
      )
    }

    const url = new URL(c.req.url)
    const path = url.pathname.startsWith(MOUNT)
      ? url.pathname.slice(MOUNT.length)
      : url.pathname

    const method = c.req.method.toUpperCase()

    // Only read a body for methods that carry one. An unparseable body
    // becomes `null` and the domain reports it as invalid syntax with
    // the right SCIM envelope, rather than throwing here.
    let body: unknown = null
    if (method === "POST" || method === "PUT" || method === "PATCH") {
      const raw = await c.req.raw.text()
      if (raw.length > 0) {
        try {
          body = JSON.parse(raw)
        } catch {
          return scimResponse(
            400,
            scimErrorBody(
              400,
              "request body is not valid JSON",
              "invalidSyntax",
            ),
          )
        }
      }
    }

    const issuer = c.get("issuerUrl")
    const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer

    const result = await handleScimRequest({
      tenant,
      method,
      path,
      query: url.searchParams,
      body,
      authorization: c.req.header("authorization") ?? null,
      baseUrl: `${base}${MOUNT}`,
      directory: deps.scimDirectory,
    })

    return scimResponse(result.status, result.body, result.headers ?? {})
  }
}
