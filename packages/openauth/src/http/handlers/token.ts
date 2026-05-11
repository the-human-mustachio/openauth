/**
 * `POST /token` handler.
 *
 * Accepts `application/x-www-form-urlencoded` (RFC 6749 §3.2). Discriminates
 * on `grant_type`:
 *   - `authorization_code` → `exchangeCode`
 *   - `refresh_token`      → `refreshTokens`
 *
 * `client_credentials` arrives in Phase 5 alongside the m2m method.
 *
 * Client authentication: secrets can ride either in the form body
 * (`client_secret`) or in the `Authorization: Basic` header. Both are
 * accepted; the header takes precedence.
 *
 * The token endpoint does NOT consult the tenant middleware — every code /
 * refresh token carries its tenant on its payload, so the auth-code or
 * refresh-token snapshot is authoritative.
 */
import { clientCredentialsGrant } from "../../domain/client-credentials"
import { exchangeCode } from "../../domain/token"
import { refreshTokens } from "../../domain/refresh"
import { isErr } from "../../types/result"
import { authError } from "../../types/error"

import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"
import { tokenRequestSchema } from "../schemas/token"

export function makeTokenHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const body = await readFormBody(c.req.raw)
    if (!body) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest("body must be application/x-www-form-urlencoded"),
      )
    }

    const basic = parseBasicAuth(c.req.header("authorization") ?? null)
    if (basic) {
      body.set("client_id", basic.id)
      body.set("client_secret", basic.secret)
    }

    const parsed = tokenRequestSchema.safeParse(
      Object.fromEntries(body.entries()),
    )
    if (!parsed.success) {
      const first = parsed.error.issues[0]
      // RFC 6749 §5.2 maps grant_type problems to `unsupported_grant_type`.
      if (first?.path[0] === "grant_type") {
        return tokenEndpointErrorResponse(
          authError.unsupportedGrantType(
            first.message ?? "unsupported grant_type",
          ),
        )
      }
      return tokenEndpointErrorResponse(
        authError.invalidRequest(first?.message ?? "invalid request"),
      )
    }
    const req = parsed.data

    if (req.grant_type === "authorization_code") {
      const result = await exchangeCode(
        {
          grantType: "authorization_code",
          code: req.code,
          redirectUri: req.redirect_uri,
          clientId: req.client_id,
          ...(req.client_secret !== undefined
            ? { clientSecret: req.client_secret }
            : {}),
          ...(req.code_verifier !== undefined
            ? { codeVerifier: req.code_verifier }
            : {}),
        },
        {
          configStore: deps.configStore,
          tokenStore: deps.tokenStore,
          keyStore: deps.keyStore,
          ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
          success: deps.success,
          ...(deps.persistUpstreamTokens
            ? { persistUpstreamTokens: deps.persistUpstreamTokens }
            : {}),
          issuerUrl: c.get("issuerUrl"),
          clock: deps.clock,
        },
      )
      if (isErr(result)) return tokenEndpointErrorResponse(result.error)
      return jsonResponse(result.value)
    }

    if (req.grant_type === "client_credentials") {
      // Resolve tenant — client_credentials carries no auth code, so we
      // call the user-supplied resolver against the /token request.
      const tenantRes = await deps.resolveTenant(c.req.raw)
      if (isErr(tenantRes)) {
        return tokenEndpointErrorResponse(tenantRes.error)
      }
      const params: Record<string, string> = {}
      for (const [k, v] of body.entries()) {
        if (typeof v === "string") params[k] = v
      }
      const result = await clientCredentialsGrant(
        {
          grantType: "client_credentials",
          clientId: req.client_id,
          clientSecret: req.client_secret,
          ...(req.scope !== undefined ? { scope: req.scope } : {}),
          params,
        },
        {
          configStore: deps.configStore,
          tokenStore: deps.tokenStore,
          keyStore: deps.keyStore,
          ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
          methodCache: deps.methodCache,
          success: deps.success,
          ...(deps.persistUpstreamTokens
            ? { persistUpstreamTokens: deps.persistUpstreamTokens }
            : {}),
          issuerUrl: c.get("issuerUrl"),
          clock: deps.clock,
        },
        tenantRes.value,
      )
      if (isErr(result)) return tokenEndpointErrorResponse(result.error)
      return jsonResponse(result.value)
    }

    // refresh_token
    const refreshResult = await refreshTokens(
      {
        grantType: "refresh_token",
        refreshToken: req.refresh_token,
        ...(req.scope !== undefined ? { scope: req.scope } : {}),
        ...(req.client_id !== undefined ? { clientId: req.client_id } : {}),
        ...(req.client_secret !== undefined
          ? { clientSecret: req.client_secret }
          : {}),
      },
      {
        configStore: deps.configStore,
        tokenStore: deps.tokenStore,
        keyStore: deps.keyStore,
        ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
        issuerUrl: c.get("issuerUrl"),
        clock: deps.clock,
      },
    )
    if (isErr(refreshResult)) return tokenEndpointErrorResponse(refreshResult.error)
    return jsonResponse(refreshResult.value)
  }
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      pragma: "no-cache",
    },
  })
}

async function readFormBody(req: Request): Promise<URLSearchParams | null> {
  const ct = req.headers.get("content-type") ?? ""
  if (!ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return null
  }
  const text = await req.text()
  return new URLSearchParams(text)
}

function parseBasicAuth(header: string | null): { id: string; secret: string } | null {
  if (!header) return null
  const m = /^Basic\s+(.+)$/i.exec(header)
  if (!m || !m[1]) return null
  try {
    const decoded = atob(m[1])
    const colon = decoded.indexOf(":")
    if (colon === -1) return null
    return {
      id: decodeURIComponent(decoded.slice(0, colon)),
      secret: decodeURIComponent(decoded.slice(colon + 1)),
    }
  } catch {
    return null
  }
}
