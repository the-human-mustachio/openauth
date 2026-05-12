/**
 * Tenant resolution + callback-recovery middleware.
 *
 * Phase 3 ships the mac-state recovery path. Mechanisms #2 (partitioned
 * host) and #3 (`flowId`-in-URI) are scaffolded but not yet plumbed end-to-
 * end (per plan §"Phase 2 — Deferred"); the framework currently falls back
 * to `resolveTenant` when the state envelope is absent or invalid, so users
 * who want partitioned-host deployments can implement the lookup inside
 * their own `resolveTenant`.
 *
 * Order on `/cb/*`:
 *   1. If `state` MAC-verifies → `mac-state`. `resolveTenant` is NOT called.
 *   2. Else fall through to `resolveTenant` (host-plus-* deployments do the
 *      host inspection there).
 *
 * Order on all other paths: `resolveTenant` directly.
 */
import type { MiddlewareHandler } from "hono"

import { verifyStateEnvelope } from "../../domain/state-envelope"
import { isErr } from "../../types/result"
import type {
  TenantConfig,
  TenantContext,
  TenantId,
  TenantRecovery,
} from "../../types/tenant"

import { parseCookieHeader } from "../cookies"
import type { HttpDeps, HttpEnv } from "../context"
import {
  authorizeDirectErrorResponse,
  tokenEndpointErrorResponse,
} from "../errors"
import { authError } from "../../types/error"

function isCallbackPath(pathname: string): boolean {
  return pathname.startsWith("/cb/")
}

/**
 * Initial pass — parse cookies + resolve issuer URL. Runs unconditionally.
 */
export function bootstrapMiddleware(
  deps: HttpDeps,
): MiddlewareHandler<HttpEnv> {
  return async (c, next) => {
    const cookies = parseCookieHeader(c.req.header("cookie") ?? null)
    c.set("cookies", cookies)
    c.set("issuerUrl", deps.resolveIssuer(c.req.raw))
    c.set("tenant", null)
    c.set("recovery", null)
    await next()
  }
}

/**
 * Tenant + recovery resolution middleware. Mount on routes that need a
 * tenant in scope (`/authorize`, method dispatch, `/cb/*`). Token endpoints
 * derive tenant from the auth code's snapshot — they skip this middleware.
 */
export function tenantMiddleware(deps: HttpDeps): MiddlewareHandler<HttpEnv> {
  return async (c, next) => {
    const url = new URL(c.req.url)

    if (isCallbackPath(url.pathname)) {
      const recovery = await runCallbackRecovery(c.req.raw, deps)
      c.set("recovery", recovery)
      if (recovery.kind !== "fresh-request") {
        const cfg = await deps.configStore.getTenantConfig(recovery.tenantId)
        if (isErr(cfg)) {
          return tokenEndpointErrorResponse(cfg.error)
        }
        const customCb = deps.buildCustomContext
          ? await deps.buildCustomContext(c.req.raw)
          : {}
        c.set(
          "tenant",
          buildTenantContext(c.req.raw, recovery.tenantId, cfg.value, customCb),
        )
        return next()
      }
    }

    const resolved = await deps.resolveTenant(c.req.raw)
    if (isErr(resolved)) {
      // For /authorize, surface as plain text (open-redirector defense — we
      // don't have a verified RP yet). For other paths, JSON suffices.
      if (url.pathname === "/authorize") {
        return authorizeDirectErrorResponse(resolved.error)
      }
      return tokenEndpointErrorResponse(resolved.error)
    }
    const tenantId = resolved.value
    const cfg = await deps.configStore.getTenantConfig(tenantId)
    if (isErr(cfg)) {
      const err =
        cfg.error.code === "tenant_not_found"
          ? authError.invalidRequest(cfg.error.description, "tenant")
          : cfg.error
      if (url.pathname === "/authorize") {
        return authorizeDirectErrorResponse(err)
      }
      return tokenEndpointErrorResponse(err)
    }
    const custom = deps.buildCustomContext
      ? await deps.buildCustomContext(c.req.raw)
      : {}
    c.set("tenant", buildTenantContext(c.req.raw, tenantId, cfg.value, custom))
    await next()
  }
}

function buildTenantContext(
  req: Request,
  id: TenantId,
  config: TenantConfig,
  custom: Record<string, unknown>,
): TenantContext {
  return {
    id,
    config,
    request: { raw: req, custom },
  }
}

async function runCallbackRecovery(
  req: Request,
  deps: HttpDeps,
): Promise<TenantRecovery> {
  const state = await extractStateParam(req)
  if (state) {
    const env = await verifyStateEnvelope(state, deps.stateKeys)
    if (env.ok) {
      return {
        kind: "mac-state",
        tenantId: env.value.tenantId,
        flowId: env.value.flowId,
      }
    }
  }
  return { kind: "fresh-request" }
}

/**
 * Pull `state` from the query for GET callbacks, or from a form body for
 * POST callbacks (Apple's `response_mode=form_post`). The body is cloned
 * so the handler can still read it.
 */
async function extractStateParam(req: Request): Promise<string | null> {
  const url = new URL(req.url)
  const fromQuery = url.searchParams.get("state")
  if (fromQuery) return fromQuery
  if (req.method !== "POST") return null
  const ct = req.headers.get("content-type") ?? ""
  if (!ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return null
  }
  try {
    const text = await req.clone().text()
    return new URLSearchParams(text).get("state")
  } catch {
    return null
  }
}
