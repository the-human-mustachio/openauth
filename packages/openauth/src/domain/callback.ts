/**
 * `handleCallback` — process the upstream provider's redirect back to the
 * IdP. The framework:
 *
 *   1. Recovers `(tenantId, flowId)` from the MAC-bound `state` envelope.
 *   2. Atomically `consumeFlow(flowId)` — single delete-on-read, returns
 *      the full `FlowRecord`.
 *   3. Runs the **state-flow consistency check** (tenant, nonce, host,
 *      path). Any mismatch → `invalid_request` + corresponding audit.
 *   4. Loads tenant config + resolves the method via `MethodCache`.
 *   5. Dispatches the method's `GET /callback` handler.
 *   6. On `success`, snapshots the in-memory `FlowRecord` into the
 *      auth-code payload via `TokenStore.saveCode` and returns
 *      `issue-code`. `methodState` is NOT snapshotted.
 *
 * Phase 2 implements the `mac-state` recovery only. Recovery mechanisms
 * #2 (partitioned-host) and #3 (`flowId`-in-URI) are wired in Phase 3
 * alongside the HTTP layer that knows the request's host / path /
 * registered redirect URIs.
 */
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { SessionStore } from "../ports/session-store"
import type { TokenStore } from "../ports/token-store"
import type { AuditLog } from "../ports/audit-log"
import type { AuthError } from "../types/error"
import { authError } from "../types/error"
import type { FlowRecord } from "../types/flow"
import type { MethodResult, SetCookie, CachePolicy } from "../types/method"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { StateKeyRing, TenantContext } from "../types/tenant"

import { safeAudit } from "./audit"
import { randomToken } from "./crypto"
import { MethodCache } from "./method-cache"
import { dispatchMethod } from "./method-dispatch"
import { saveEncryptedCode } from "./token"
import { verifyStateEnvelope } from "./state-envelope"
import { AUTH_CODE_TTL_MS } from "./authorize"

export type CallbackOutput =
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

export type HandleCallbackInput = {
  /** The raw `Request` for the upstream provider's redirect. */
  rawRequest: Request
  cookies: ReadonlyMap<string, string>
}

export type HandleCallbackDeps = {
  configStore: ConfigStore
  sessionStore: SessionStore
  tokenStore: TokenStore
  /** Needed for at-rest encryption of the code payload — see `domain/token.ts`. */
  keyStore: KeyStore
  auditLog?: AuditLog
  methodCache: MethodCache
  stateKeys: StateKeyRing
  clock: () => number
  newCodeId?: () => string
  /**
   * Build the `TenantContext.request.custom` blob. Wired through from
   * `IdPOptions.buildCustomContext` by the HTTP layer; if absent the
   * blob is `{}`.
   */
  buildCustomContext?: (
    req: Request,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>
}

export async function handleCallback(
  input: HandleCallbackInput,
  deps: HandleCallbackDeps,
): Promise<Result<CallbackOutput, AuthError>> {
  const url = new URL(input.rawRequest.url)
  const state = url.searchParams.get("state")
  if (!state) {
    return err(authError.invalidRequest("missing state parameter", "state"))
  }
  const envelopeRes = await verifyStateEnvelope(state, deps.stateKeys)
  if (isErr(envelopeRes)) {
    await safeAudit(deps, {
      kind: "flow_replay_attempt",
      tenantId: null,
      flowId: "unknown",
      timestamp: deps.clock(),
    })
    return err(authError.invalidRequest(envelopeRes.error.description, "state"))
  }
  const envelope = envelopeRes.value

  const flowRes = await deps.sessionStore.consumeFlow(envelope.flowId)
  if (isErr(flowRes)) {
    await safeAudit(deps, {
      kind: "flow_replay_attempt",
      tenantId: envelope.tenantId,
      flowId: envelope.flowId,
      timestamp: deps.clock(),
    })
    return err(authError.invalidRequest(flowRes.error.description, "state"))
  }
  const flow = flowRes.value

  // 3. State-flow consistency check.
  if (envelope.tenantId !== flow.tenantId) {
    await safeAudit(deps, {
      kind: "flow_tenant_mismatch",
      stateTenantId: envelope.tenantId,
      flowTenantId: flow.tenantId,
      flowId: flow.flowId,
      timestamp: deps.clock(),
    })
    return err(authError.invalidRequest("tenant mismatch", "state"))
  }
  if (envelope.nonce !== flow.nonce) {
    return err(authError.invalidRequest("nonce mismatch", "state"))
  }
  if (url.host !== flow.callbackHost) {
    await safeAudit(deps, {
      kind: "flow_callback_mismatch",
      tenantId: flow.tenantId,
      flowId: flow.flowId,
      expected: { host: flow.callbackHost, path: flow.callbackPath },
      actual: { host: url.host, path: url.pathname },
      timestamp: deps.clock(),
    })
    return err(authError.invalidRequest("host mismatch", "state"))
  }
  if (normalizePath(url.pathname) !== normalizePath(flow.callbackPath)) {
    await safeAudit(deps, {
      kind: "flow_callback_mismatch",
      tenantId: flow.tenantId,
      flowId: flow.flowId,
      expected: { host: flow.callbackHost, path: flow.callbackPath },
      actual: { host: url.host, path: url.pathname },
      timestamp: deps.clock(),
    })
    return err(authError.invalidRequest("path mismatch", "state"))
  }

  // 4. Load tenant + resolve method.
  const cfgRes = await deps.configStore.getTenantConfig(flow.tenantId)
  if (isErr(cfgRes)) return err(cfgRes.error)
  const tenant: TenantContext = {
    id: flow.tenantId,
    config: cfgRes.value,
    request: {
      raw: input.rawRequest,
      custom: deps.buildCustomContext
        ? await deps.buildCustomContext(input.rawRequest)
        : {},
    },
  }
  const methodRes = await deps.methodCache.resolve(cfgRes.value, flow.methodId)
  if (isErr(methodRes)) return err(methodRes.error)

  // 5. Dispatch.
  const dispatched = await dispatchMethod({
    method: methodRes.value,
    route: "GET /callback",
    tenant,
    request: input.rawRequest,
    subPath: "/callback",
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
  deps: HandleCallbackDeps,
): Promise<Result<CallbackOutput, AuthError>> {
  switch (result.kind) {
    case "success": {
      const code = (deps.newCodeId ?? randomToken)()
      const now = deps.clock()
      const saved = await saveEncryptedCode(
        code,
        {
          tenantId: flow.tenantId,
          clientId: flow.clientId,
          appRedirectUri: flow.appRedirectUri,
          appState: flow.appState,
          scopes: flow.scopes,
          audience: flow.audience,
          clientPkce: flow.clientPkce,
          methodId: flow.methodId,
          methodKind: flow.methodKind,
          context: flow.context ?? null,
          providerSubject: result.providerSubject,
          properties: result.properties,
          expiresAt: now + AUTH_CODE_TTL_MS,
        },
        AUTH_CODE_TTL_MS,
        { keyStore: deps.keyStore, tokenStore: deps.tokenStore },
      )
      if (isErr(saved)) return err(saved.error)
      return ok({
        kind: "issue-code",
        code,
        appRedirectUri: flow.appRedirectUri,
        appState: flow.appState,
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
      await safeAudit(deps, {
        kind: "authorize_failed",
        tenantId: flow.tenantId,
        clientId: flow.clientId,
        methodId: flow.methodId,
        methodKind: flow.methodKind,
        flowId: flow.flowId,
        reason: result.error.code,
        timestamp: deps.clock(),
      })
      return err(result.error)
  }
}

function normalizePath(p: string): string {
  return p.replace(/\/+$/, "")
}
