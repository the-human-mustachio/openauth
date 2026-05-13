/**
 * `handleMethodRoute` — the third pipeline.
 *
 * `/authorize` and `/cb/:methodId` are the two pipelines that produce a
 * flow record and consume it respectively. Credential-style methods
 * (password, code, passkey) additionally need a way to make in-flight
 * POSTs against the IdP — submitting a login form, asking for a one-time
 * code, completing a WebAuthn ceremony. The HTTP layer mounts these at
 * `/m/<methodId>/<subPath>` and delegates here.
 *
 * Responsibilities:
 *   1. Read `flowId` from the framework-set HttpOnly `idp.flow` cookie.
 *      No cookie → `invalid_request` (the user lost their flow).
 *   2. `SessionStore.readFlow(flowId)` — peek, do not consume. Methods may
 *      need multiple round trips before completing (e.g. send-code →
 *      verify-code).
 *   3. Tenant must match the cookie's flow. If the request's tenant
 *      (resolved via `resolveTenant`) disagrees with the flow's tenant,
 *      audit `flow_tenant_mismatch` and reject. This is the same invariant
 *      the upstream-callback path enforces.
 *   4. Dispatch the method's `<METHOD> <subPath>` route.
 *   5. Translate `MethodResult`:
 *      - `challenge` → return response (methodState merged before send).
 *      - `success`   → `consumeFlow`, snapshot into auth code, return
 *                      `issue-code` for the HTTP layer to redirect.
 *      - `denied`    → return reason; HTTP layer renders.
 *      - `error`     → propagated.
 */
import type { AuditLog } from "../ports/audit-log"
import type { KeyStore } from "../ports/key-store"
import type { SessionStore } from "../ports/session-store"
import type { TokenStore } from "../ports/token-store"
import { authError, type AuthError } from "../types/error"
import type { FlowRecord } from "../types/flow"
import type { MethodResult, CachePolicy, SetCookie } from "../types/method"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantContext } from "../types/tenant"

import { safeAudit } from "./audit"
import { AUTH_CODE_TTL_MS } from "./authorize"
import { randomToken } from "./crypto"
import { MethodCache } from "./method-cache"
import { dispatchMethod, type RouteKey } from "./method-dispatch"
import { saveEncryptedCode } from "./token"

export type MethodRouteOutput =
  | {
      kind: "issue-code"
      code: string
      appRedirectUri: string
      appState: string | null
    }
  | {
      kind: "challenge"
      response: Response
      setCookies: SetCookie[]
      cache?: CachePolicy
    }
  | { kind: "denied"; reason: string; setCookies: SetCookie[] }

export type HandleMethodRouteInput = {
  rawRequest: Request
  tenant: TenantContext
  /** Tenant-local instance id (`MethodConfig.id`) parsed from the URL. */
  methodId: string
  /** Path within the method's mount, e.g. `"/login"`. */
  subPath: string
  /** HTTP method of the incoming request: `"GET"` or `"POST"`. */
  httpMethod: "GET" | "POST"
  /** flowId from the `idp.flow` cookie. */
  flowId: string
  cookies: ReadonlyMap<string, string>
}

export type HandleMethodRouteDeps = {
  sessionStore: SessionStore
  tokenStore: TokenStore
  /** Needed for at-rest encryption of the code payload — see `domain/token.ts`. */
  keyStore: KeyStore
  auditLog?: AuditLog
  methodCache: MethodCache
  clock: () => number
  newCodeId?: () => string
}

export async function handleMethodRoute(
  input: HandleMethodRouteInput,
  deps: HandleMethodRouteDeps,
): Promise<Result<MethodRouteOutput, AuthError>> {
  // 1. Peek at the flow record.
  const flowRes = await deps.sessionStore.readFlow(input.flowId)
  if (isErr(flowRes)) return err(flowRes.error)
  const flow = flowRes.value

  // 2. Tenant must match.
  if (flow.tenantId !== input.tenant.id) {
    await safeAudit(deps, {
      kind: "flow_tenant_mismatch",
      stateTenantId: input.tenant.id,
      flowTenantId: flow.tenantId,
      flowId: flow.flowId,
      timestamp: deps.clock(),
    })
    return err(authError.invalidRequest("tenant mismatch", "flow"))
  }

  // 3. Resolve the method.
  if (flow.methodId !== input.methodId) {
    return err(
      authError.invalidRequest(
        `method "${input.methodId}" does not own flow "${flow.flowId}" (expected "${flow.methodId}")`,
        "methodId",
      ),
    )
  }
  const methodRes = await deps.methodCache.resolve(
    input.tenant.config,
    input.methodId,
  )
  if (isErr(methodRes)) return err(methodRes.error)

  // 4. Dispatch.
  const route: RouteKey = `${input.httpMethod} ${input.subPath}`
  const dispatched = await dispatchMethod({
    method: methodRes.value,
    route,
    tenant: input.tenant,
    request: input.rawRequest,
    subPath: input.subPath,
    flow,
    cookies: input.cookies,
    sessionStore: deps.sessionStore,
    dispatch: null,
  })
  if (isErr(dispatched)) return err(dispatched.error)
  return translate(dispatched.value, flow, deps)
}

async function translate(
  result: MethodResult<unknown, unknown>,
  flow: FlowRecord,
  deps: HandleMethodRouteDeps,
): Promise<Result<MethodRouteOutput, AuthError>> {
  switch (result.kind) {
    case "success": {
      const consumed = await deps.sessionStore.consumeFlow(flow.flowId)
      if (isErr(consumed)) return err(consumed.error)
      // Use the consumed record (the one we already had via readFlow may be
      // slightly stale relative to the most recent updateFlowMethodState).
      const final = consumed.value
      const code = (deps.newCodeId ?? randomToken)()
      const now = deps.clock()
      const saved = await saveEncryptedCode(
        code,
        {
          tenantId: final.tenantId,
          clientId: final.clientId,
          appRedirectUri: final.appRedirectUri,
          appState: final.appState,
          scopes: final.scopes,
          audience: final.audience,
          clientPkce: final.clientPkce,
          methodId: final.methodId,
          methodKind: final.methodKind,
          context: final.context ?? null,
          providerSubject: result.providerSubject,
          properties: result.properties,
          ...(final.appNonce !== undefined ? { appNonce: final.appNonce } : {}),
          authTime: Math.floor(now / 1000),
          expiresAt: now + AUTH_CODE_TTL_MS,
        },
        AUTH_CODE_TTL_MS,
        { keyStore: deps.keyStore, tokenStore: deps.tokenStore },
      )
      if (isErr(saved)) return err(saved.error)
      return ok({
        kind: "issue-code",
        code,
        appRedirectUri: final.appRedirectUri,
        appState: final.appState,
      })
    }
    case "challenge":
      return ok({
        kind: "challenge",
        response: result.response,
        setCookies: result.setCookies ?? [],
        ...(result.cache !== undefined ? { cache: result.cache } : {}),
      })
    case "denied":
      await safeAudit(deps, {
        kind: "authorize_failed",
        tenantId: flow.tenantId,
        clientId: flow.clientId,
        methodId: flow.methodId,
        methodKind: flow.methodKind,
        flowId: flow.flowId,
        reason: result.reason,
        timestamp: deps.clock(),
      })
      return ok({
        kind: "denied",
        reason: result.reason,
        setCookies: result.setCookies ?? [],
      })
    case "error":
      return err(result.error)
  }
}
