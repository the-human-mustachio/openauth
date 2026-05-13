/**
 * `POST /register` — RFC 7591 Dynamic Client Registration.
 *
 * Body: `application/json`. Tenant resolved via the standard middleware.
 * The framework validates structure here and defers persistence to the
 * `IdPOptions.registerClient` hook (in `domain/register.ts`).
 *
 * Per RFC 7591 §3.2.1, success returns HTTP 201 with JSON body.
 */
import { registerNewClient } from "../../domain/register"
import { authError } from "../../types/error"
import type { RegisterClientRequest } from "../../types/idp"
import { isErr } from "../../types/result"

import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"
import { registerBodySchema } from "../schemas/register"

export function makeRegisterHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const tenant = c.get("tenant")
    if (!tenant) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("tenant unresolved"),
      )
    }
    const ct = (c.req.header("content-type") ?? "").toLowerCase()
    if (!ct.startsWith("application/json")) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("body must be application/json"),
      )
    }
    let raw: unknown
    try {
      raw = await c.req.raw.json()
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e)
      return tokenEndpointErrorResponse(
        authError.invalidRequest(`malformed JSON: ${reason}`),
      )
    }
    const parsed = registerBodySchema.safeParse(raw)
    if (!parsed.success) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(
          parsed.error.issues[0]?.message ?? "invalid request",
        ),
      )
    }
    // Schema is `.passthrough()` (RFC 7591 allows extension metadata
    // fields); the declared `RegisterClientRequest` fields are all
    // statically present in `parsed.data`. This cast just drops the
    // passthrough's `[k: string]: unknown` index signature so the
    // downstream domain function sees the typed contract.
    const request = parsed.data as RegisterClientRequest

    const res = await registerNewClient(request, tenant, {
      ...(deps.registerClient ? { registerClient: deps.registerClient } : {}),
      clock: deps.clock,
    })
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
