/**
 * OIDC `/userinfo` handler (OIDC Core §5.3). Accepts `GET` or `POST` per
 * the spec. Supports both `Authorization: Bearer ...` (RFC 6750) and
 * `Authorization: DPoP ...` (RFC 9449) — the domain layer enforces the
 * proof match against the access token's `cnf.jkt` when bound.
 */
import { canonicalHtu } from "../../domain/dpop"
import { userinfo } from "../../domain/userinfo"
import { isErr } from "../../types/result"

import type { HttpContext, HttpDeps } from "../context"

export function makeUserinfoHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const auth = extractAuthorization(c.req.header("authorization") ?? null)
    if (!auth) {
      return wwwAuthenticateResponse(
        "Bearer",
        "invalid_token",
        "missing bearer / DPoP token",
        401,
      )
    }

    const dpopProof = c.req.header("dpop") ?? undefined
    const res = await userinfo(
      {
        accessToken: auth.token,
        scheme: auth.scheme,
        ...(dpopProof !== undefined ? { dpopProof } : {}),
        htu: canonicalHtu(c.req.url),
        htm: c.req.method.toUpperCase(),
        nowSec: Math.floor(deps.clock() / 1000),
      },
      {
        keyStore: deps.keyStore,
        tokenStore: deps.tokenStore,
        issuerUrl: c.get("issuerUrl"),
      },
    )
    if (isErr(res)) {
      const error = res.error
      const scheme = auth.scheme
      const wireError =
        error.code === "invalid_dpop_proof" ? "invalid_dpop_proof" : "invalid_token"
      return wwwAuthenticateResponse(scheme, wireError, error.description, 401)
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

function extractAuthorization(
  header: string | null,
): { scheme: "Bearer" | "DPoP"; token: string } | null {
  if (!header) return null
  const m = /^(Bearer|DPoP)\s+(.+)$/i.exec(header)
  if (!m || !m[1] || !m[2]) return null
  const scheme = m[1].toLowerCase() === "dpop" ? "DPoP" : "Bearer"
  return { scheme, token: m[2] }
}

function wwwAuthenticateResponse(
  scheme: "Bearer" | "DPoP",
  error: string,
  description: string,
  status: number,
): Response {
  return new Response(
    JSON.stringify({ error, error_description: description }),
    {
      status,
      headers: {
        "content-type": "application/json",
        "www-authenticate": `${scheme} error="${error}"`,
      },
    },
  )
}
