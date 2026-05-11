/**
 * OIDC `/userinfo` handler (OIDC Core §5.3). Accepts `GET` or `POST` per
 * the spec.
 */
import { userinfo } from "../../domain/userinfo"
import { isErr } from "../../types/result"

import type { HttpContext, HttpDeps } from "../context"

export function makeUserinfoHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const bearer = extractBearer(c.req.header("authorization") ?? null)
    if (!bearer) {
      const r = new Response(
        JSON.stringify({
          error: "invalid_token",
          error_description: "missing bearer token",
        }),
        {
          status: 401,
          headers: {
            "content-type": "application/json",
            "www-authenticate": 'Bearer realm="userinfo"',
          },
        },
      )
      return r
    }

    const res = await userinfo(bearer, {
      keyStore: deps.keyStore,
      issuerUrl: c.get("issuerUrl"),
    })
    if (isErr(res)) {
      // OIDC userinfo returns 401 on invalid token (vs. 400 elsewhere).
      const err = res.error
      return new Response(
        JSON.stringify({
          error: "invalid_token",
          error_description: err.description,
        }),
        {
          status: 401,
          headers: {
            "content-type": "application/json",
            "www-authenticate": `Bearer error="invalid_token"`,
          },
        },
      )
    }

    return new Response(JSON.stringify(res.value), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    })
  }
}

function extractBearer(header: string | null): string | null {
  if (!header) return null
  const m = /^Bearer\s+(.+)$/i.exec(header)
  return m?.[1] ?? null
}
