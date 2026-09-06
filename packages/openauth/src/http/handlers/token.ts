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
import { canonicalHtu, verifyDpopProof } from "../../domain/dpop"
import { exchangeCode } from "../../domain/token"
import { exchangeToken } from "../../domain/token-exchange"
import { refreshTokens } from "../../domain/refresh"
import { isErr } from "../../types/result"
import { authError } from "../../types/error"

import type { HttpContext, HttpDeps } from "../context"
import { tokenEndpointErrorResponse } from "../errors"
import { injectResolverHints } from "../resolver"
import { tokenRequestSchema } from "../schemas/token"

export function makeTokenHandler(deps: HttpDeps) {
  return async (c: HttpContext): Promise<Response> => {
    const body = await readFormBody(c.req.raw)
    if (!body) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(
          "body must be application/x-www-form-urlencoded",
        ),
      )
    }

    // `Authorization` carries Basic client auth on /token. DPoP travels in
    // its own `DPoP:` header (RFC 9449 §5) — never inside `Authorization`.
    // Parsing Basic first lets a confidential client present its secret
    // alongside a DPoP proof.
    const basic = parseBasicAuth(c.req.header("authorization") ?? null)
    if (basic) {
      body.set("client_id", basic.id)
      body.set("client_secret", basic.secret)
    }

    // RFC 9449 §5.1 — verify any presented DPoP proof against this
    // request's actual method + URI. Absent header is fine here (the
    // grant-specific path enforces `dpopRequired`).
    const dpopHeader = c.req.header("dpop") ?? null
    let dpopJkt: string | undefined
    if (dpopHeader) {
      const dpopRes = await verifyDpopProof(
        {
          proofJwt: dpopHeader,
          htu: canonicalHtu(c.req.url),
          htm: "POST",
          nowSec: Math.floor(deps.clock() / 1000),
        },
        { tokenStore: deps.tokenStore },
      )
      if (isErr(dpopRes)) {
        // RFC 9449 §11.1 replay → first-class audit event so operators /
        // SIEM can spot stolen-key probing distinct from generic proof
        // verification failures.
        const errVal = dpopRes.error
        if (
          errVal.code === "invalid_dpop_proof" &&
          errVal.replaySignal &&
          deps.auditLog
        ) {
          await deps.auditLog.log({
            kind: "dpop_replay_detected",
            tenantId: null,
            jtiPrefix: errVal.replaySignal.jti.slice(0, 16),
            timestamp: deps.clock(),
          })
        }
        return tokenEndpointErrorResponse(errVal)
      }
      dpopJkt = dpopRes.value.jkt
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
          ...(dpopJkt !== undefined ? { dpopJkt } : {}),
        },
        {
          configStore: deps.configStore,
          tokenStore: deps.tokenStore,
          keyStore: deps.keyStore,
          ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
          success: deps.success,
          subjects: deps.subjects,
          ...(deps.persistUpstreamTokens
            ? { persistUpstreamTokens: deps.persistUpstreamTokens }
            : {}),
          issuerUrl: c.get("issuerUrl"),
          clock: deps.clock,
          ...(deps.customScopeClaims !== undefined
            ? { customScopeClaims: deps.customScopeClaims }
            : {}),
        },
      )
      if (isErr(result)) return tokenEndpointErrorResponse(result.error)
      return jsonResponse(result.value)
    }

    if (req.grant_type === "client_credentials") {
      // Resolve tenant — client_credentials carries no auth code, so we
      // call the user-supplied resolver against the /token request. The
      // canonical resolver pattern (INTEGRATION.md §5.1) reads `client_id`
      // from URL search params, but the m2m grant carries client_id in the
      // form body / Basic auth — never the URL. Inject the parsed
      // `client_id` into a synthesized request so resolvers using the
      // canonical pattern work for m2m without an extra hook.
      const tenantRes = await deps.resolveTenant(
        injectResolverHints(c.req.raw, { client_id: req.client_id }),
      )
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
          subjects: deps.subjects,
          ...(deps.persistUpstreamTokens
            ? { persistUpstreamTokens: deps.persistUpstreamTokens }
            : {}),
          issuerUrl: c.get("issuerUrl"),
          clock: deps.clock,
          ...(deps.customScopeClaims !== undefined
            ? { customScopeClaims: deps.customScopeClaims }
            : {}),
        },
        tenantRes.value,
      )
      if (isErr(result)) return tokenEndpointErrorResponse(result.error)
      return jsonResponse(result.value)
    }

    if (req.grant_type === "refresh_token") {
      const refreshResult = await refreshTokens(
        {
          grantType: "refresh_token",
          refreshToken: req.refresh_token,
          ...(req.scope !== undefined ? { scope: req.scope } : {}),
          ...(req.client_id !== undefined ? { clientId: req.client_id } : {}),
          ...(req.client_secret !== undefined
            ? { clientSecret: req.client_secret }
            : {}),
          ...(dpopJkt !== undefined ? { dpopJkt } : {}),
        },
        {
          configStore: deps.configStore,
          tokenStore: deps.tokenStore,
          keyStore: deps.keyStore,
          ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
          issuerUrl: c.get("issuerUrl"),
          clock: deps.clock,
          ...(deps.customScopeClaims !== undefined
            ? { customScopeClaims: deps.customScopeClaims }
            : {}),
        },
      )
      if (isErr(refreshResult))
        return tokenEndpointErrorResponse(refreshResult.error)
      return jsonResponse(refreshResult.value)
    }

    // RFC 8693 token-exchange. Delegation (actor_token) is out of scope;
    // reject up front so we don't silently accept an actor and ignore it.
    if (req.actor_token !== undefined) {
      return tokenEndpointErrorResponse(
        authError.invalidRequest(
          "actor_token (delegation) is not supported; only impersonation / audience-switch is in scope",
        ),
      )
    }
    const exchangeResult = await exchangeToken(
      {
        grantType: req.grant_type,
        subjectToken: req.subject_token,
        audience: req.audience,
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
        ...(deps.exchangeAudience
          ? { exchangeAudience: deps.exchangeAudience }
          : {}),
        issuerUrl: c.get("issuerUrl"),
        clock: deps.clock,
        ...(deps.customScopeClaims !== undefined
          ? { customScopeClaims: deps.customScopeClaims }
          : {}),
      },
    )
    if (isErr(exchangeResult)) {
      return tokenEndpointErrorResponse(exchangeResult.error)
    }
    return jsonResponse(exchangeResult.value)
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

function parseBasicAuth(
  header: string | null,
): { id: string; secret: string } | null {
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
