/**
 * `startAuthorize` — orchestrate the `/authorize` flow.
 *
 * Pure domain function over typed ports. The HTTP layer (Phase 3) parses
 * the incoming `Request` into an `AuthorizationRequest`, runs
 * `resolveTenant`, then calls into this function. No framework imports.
 *
 * Responsibilities (in order):
 *   1. Validate the request against the registered `ClientConfig` —
 *      client lookup, redirect-URI exact match, scope subset, PKCE
 *      required-when-required.
 *   2. Pick the method to dispatch to: explicit `methodId` if present,
 *      else the only enabled method, else surface a method-selection
 *      output for the UI.
 *   3. Atomically `saveFlow` the `FlowRecord` (creates the
 *      pre-callback state) under a freshly minted `flowId`.
 *   4. Mint the MAC-signed `state` envelope under the active key.
 *   5. Dispatch to the method's `GET /authorize` handler — the method
 *      builds the upstream redirect (or renders the credential form,
 *      etc.) using the `dispatch.state` / `dispatch.callbackUrl` data
 *      we supply.
 *   6. Translate the `MethodResult` into an `AuthorizeOutput`:
 *      `challenge` (HTTP layer renders), `success` (HTTP layer issues a
 *      code immediately — e.g. single-step credential flows), `denied`
 *      (OAuth `access_denied`), `error` (propagated).
 *
 * The framework writes / consumes `FlowRecord`. Methods read via
 * `MethodContext.flow` / `methodState` and request state changes via
 * `MethodResult.challenge.saveMethodState`.
 */
import type { AuditLog } from "../ports/audit-log"
import type { SessionStore } from "../ports/session-store"
import type { TokenStore } from "../ports/token-store"
import type { AuthError } from "../types/error"
import { authError } from "../types/error"
import type { FlowRecord } from "../types/flow"
import type { AuthorizationRequest } from "../types/authorization"
import type {
  AnyAuthMethodFactory,
  AuthMethod,
  MethodResult,
  SetCookie,
  CachePolicy,
} from "../types/method"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { ClientConfig, StateKeyRing, TenantContext } from "../types/tenant"

import { randomId, randomToken } from "./crypto"
import { MethodCache } from "./method-cache"
import { dispatchMethod } from "./method-dispatch"
import { mintStateEnvelope } from "./state-envelope"

/** Default 10-minute pre-callback flow lifetime per plan §"TTLs". */
export const DEFAULT_FLOW_TTL_MS = 10 * 60 * 1000

/** Default 60-second auth-code lifetime per OAuth 2.1 BCP. */
export const AUTH_CODE_TTL_MS = 60 * 1000

export type AuthorizeOutput =
  /** Render the method's challenge (UI / redirect). HTTP layer applies cookies. */
  | {
      kind: "challenge"
      response: Response
      setCookies: SetCookie[]
      cache?: CachePolicy
    }
  /**
   * Method returned synchronous success (e.g. single-step credential flow).
   * The framework has minted an auth code; HTTP layer 302s back to the RP
   * with `code` + `state` in the query.
   */
  | {
      kind: "issue-code"
      code: string
      appRedirectUri: string
      appState: string | null
    }
  /** Method denied — surface `access_denied` per OAuth 2.1. */
  | { kind: "denied"; reason: string; setCookies: SetCookie[] }
  /**
   * No `methodId` given and >1 enabled methods configured. HTTP layer
   * renders a selection page that re-requests `/authorize?methodId=…`.
   */
  | {
      kind: "select-method"
      methods: Array<{ id: string; kind: string; type: string }>
    }

export type StartAuthorizeInput = {
  request: AuthorizationRequest
  /** The raw `Request` — handed to the method via `MethodContext.request`. */
  rawRequest: Request
  tenant: TenantContext
  cookies: ReadonlyMap<string, string>
}

export type StartAuthorizeDeps = {
  sessionStore: SessionStore
  tokenStore: TokenStore
  auditLog?: AuditLog
  methodCache: MethodCache
  stateKeys: StateKeyRing
  /** Issuer URL — used to build the callback URL and threaded to methods. */
  issuerUrl: string
  /** Tenant-partitioned callback host helper. Optional (recovery mechanism #2). */
  callbackHostFor?: (tenantId: string) => string
  clock: () => number
  /** Override for testability. Defaults to `randomId` / `randomToken`. */
  newFlowId?: () => string
  newCodeId?: () => string
  newNonce?: () => string
  /** Override TTLs. */
  flowTtlMs?: number
}

export async function startAuthorize(
  input: StartAuthorizeInput,
  deps: StartAuthorizeDeps,
): Promise<Result<AuthorizeOutput, AuthError>> {
  const tenant = input.tenant
  const req = input.request

  // 1. Validate client + request shape.
  const client = tenant.config.clients.find((c) => c.id === req.clientId)
  if (!client) {
    return err(authError.invalidClient(`unknown client "${req.clientId}"`))
  }
  if (!client.redirectUris.includes(req.redirectUri)) {
    return err(
      authError.invalidRequest(
        `redirect_uri "${req.redirectUri}" not registered for client "${client.id}"`,
        "redirect_uri",
      ),
    )
  }
  if (req.responseType !== "code") {
    return err(
      authError.invalidRequest(
        `unsupported response_type "${req.responseType}" — OAuth 2.1 is code-only`,
        "response_type",
      ),
    )
  }
  const grantOk = client.grantTypes.includes("authorization_code")
  if (!grantOk) {
    return err(
      authError.unauthorizedClient(
        `client "${client.id}" is not authorized for authorization_code grant`,
      ),
    )
  }
  const scopeError = validateScopes(req.scopes, client.scopes)
  if (scopeError) return err(scopeError)
  const pkceError = validatePkceRequirement(req, client)
  if (pkceError) return err(pkceError)

  // 2. Resolve method.
  const enabled = tenant.config.methods.filter((m) => m.enabled)
  if (enabled.length === 0) {
    return err(
      authError.methodNotFound("no auth methods enabled for tenant", {}),
    )
  }
  let methodId = req.methodId
  if (!methodId) {
    if (enabled.length === 1) {
      methodId = enabled[0]!.id
    } else {
      return ok({
        kind: "select-method",
        methods: enabled.map((m) => ({ id: m.id, kind: m.kind, type: m.type })),
      })
    }
  }
  const methodResult = await deps.methodCache.resolve(tenant.config, methodId)
  if (isErr(methodResult)) return err(methodResult.error)
  const method = methodResult.value

  // 3. Create + persist FlowRecord, then mint state envelope.
  const flowId = (deps.newFlowId ?? randomId)()
  const nonce = (deps.newNonce ?? randomToken)()
  const flowTtl = deps.flowTtlMs ?? DEFAULT_FLOW_TTL_MS
  const now = deps.clock()
  const callbackHost =
    deps.callbackHostFor?.(tenant.id) ?? new URL(deps.issuerUrl).host
  const callbackPath = `/cb/${methodId}`
  const callbackUrl = `${new URL(deps.issuerUrl).protocol}//${callbackHost}${callbackPath}`

  const record: FlowRecord = {
    flowId,
    tenantId: tenant.id,
    methodId,
    methodKind: method.kind,
    clientId: client.id,
    appRedirectUri: req.redirectUri,
    callbackPath,
    callbackHost,
    appState: req.state,
    scopes: req.scopes,
    responseType: "code",
    audience: req.audience,
    prompt: req.prompt,
    uiLocales: req.uiLocales,
    nonce,
    clientPkce: req.codeChallenge
      ? { challenge: req.codeChallenge, method: "S256" }
      : undefined,
    methodState: null,
    context: tenant.request.custom,
    createdAt: now,
    expiresAt: now + flowTtl,
  }

  const saved = await deps.sessionStore.saveFlow(flowId, record, flowTtl)
  if (isErr(saved)) return err(saved.error)

  const stateEnvelope = await mintStateEnvelope(
    { tenantId: tenant.id, flowId, nonce },
    deps.stateKeys,
  )

  await audit(deps, {
    kind: "authorize_started",
    tenantId: tenant.id,
    clientId: client.id,
    methodId,
    methodKind: method.kind,
    flowId,
    timestamp: now,
  })

  // 4. Dispatch to the method's GET /authorize handler.
  const dispatched = await dispatchMethod({
    method,
    route: "GET /authorize",
    tenant,
    request: input.rawRequest,
    subPath: "/authorize",
    flow: record,
    cookies: input.cookies,
    sessionStore: deps.sessionStore,
    dispatch: {
      state: stateEnvelope,
      callbackUrl,
      issuerUrl: deps.issuerUrl,
    },
  })
  if (isErr(dispatched)) return err(dispatched.error)
  return translateMethodResult(dispatched.value, record, method, deps)
}

function validateScopes(
  requested: string[],
  allowed: string[],
): AuthError | null {
  for (const s of requested) {
    if (!allowed.includes(s)) {
      return authError.invalidScope(`scope "${s}" not allowed for client`)
    }
  }
  return null
}

function validatePkceRequirement(
  req: AuthorizationRequest,
  client: ClientConfig,
): AuthError | null {
  const requiresPkce = client.pkceRequired || client.type === "public"
  if (!requiresPkce) return null
  if (!req.codeChallenge) {
    return authError.invalidRequest(
      `client "${client.id}" requires PKCE — missing code_challenge`,
      "code_challenge",
    )
  }
  if (req.codeChallengeMethod && req.codeChallengeMethod !== "S256") {
    return authError.invalidRequest(
      `unsupported code_challenge_method "${req.codeChallengeMethod}" — S256 required`,
      "code_challenge_method",
    )
  }
  return null
}

async function translateMethodResult(
  result: MethodResult<unknown, unknown>,
  record: FlowRecord,
  _method: AuthMethod,
  deps: StartAuthorizeDeps,
): Promise<Result<AuthorizeOutput, AuthError>> {
  switch (result.kind) {
    case "challenge":
      return ok({
        kind: "challenge",
        response: result.response,
        setCookies: result.setCookies ?? [],
        ...(result.cache !== undefined ? { cache: result.cache } : {}),
      })

    case "success": {
      const issued = await issueCodeFromInlineSuccess(result, record, deps)
      return issued
    }

    case "denied":
      await audit(deps, {
        kind: "authorize_failed",
        tenantId: record.tenantId,
        clientId: record.clientId,
        methodId: record.methodId,
        methodKind: record.methodKind,
        flowId: record.flowId,
        reason: result.reason,
        timestamp: deps.clock(),
      })
      return ok({
        kind: "denied",
        reason: result.reason,
        setCookies: result.setCookies ?? [],
      })

    case "error":
      await audit(deps, {
        kind: "authorize_failed",
        tenantId: record.tenantId,
        clientId: record.clientId,
        methodId: record.methodId,
        methodKind: record.methodKind,
        flowId: record.flowId,
        reason: result.error.code,
        timestamp: deps.clock(),
      })
      return err(result.error)
  }
}

/**
 * When a method short-circuits `/authorize` with `success` (e.g. a
 * credential-form method that submits and succeeds in one round trip),
 * we consume the in-memory flow record, snapshot it into a code, and
 * return `issue-code` so the HTTP layer can redirect the user agent
 * back to the RP.
 */
async function issueCodeFromInlineSuccess(
  result: Extract<MethodResult<unknown, unknown>, { kind: "success" }>,
  record: FlowRecord,
  deps: StartAuthorizeDeps,
): Promise<Result<AuthorizeOutput, AuthError>> {
  const code = (deps.newCodeId ?? randomToken)()
  const consumed = await deps.sessionStore.consumeFlow(record.flowId)
  if (isErr(consumed)) return err(consumed.error)
  const flow = consumed.value
  const now = deps.clock()
  const saved = await deps.tokenStore.saveCode(
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
  )
  if (isErr(saved)) return err(saved.error)
  return ok({
    kind: "issue-code",
    code,
    appRedirectUri: flow.appRedirectUri,
    appState: flow.appState,
  })
}

async function audit(
  deps: { auditLog?: AuditLog },
  event: Parameters<AuditLog["log"]>[0],
): Promise<void> {
  if (!deps.auditLog) return
  try {
    await deps.auditLog.log(event)
  } catch {
    // swallow
  }
}

/** Factory map type — exported for HTTP-layer consumers. */
export type FactoryMap = Record<string, AnyAuthMethodFactory>
