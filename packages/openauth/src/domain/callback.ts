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
import { callbackTarget } from "./mount"
import { saveEncryptedCode } from "./token"
import { extractCallbackState, verifyStateEnvelope } from "./state-envelope"
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
  /**
   * Resolved tenant for this request. The SP-initiated path derives
   * the tenant from the consumed flow and ignores this. The
   * **IdP-initiated** path (unsolicited POST, no flow) has nothing to
   * derive from, so it uses this — populated by the HTTP layer from
   * the tenant middleware. Absent ⇒ IdP-initiated is not attempted.
   */
  tenant?: TenantContext
  /**
   * Per-request issuer URL (HTTP layer). The IdP-initiated path derives
   * the SP entityID / ACS from it — the same derivation the AuthnRequest
   * and metadata paths use, so the values cannot drift — and every
   * dispatched method receives it as `MethodContext.issuerUrl` to build
   * mount-prefixed URLs of its own.
   */
  issuerUrl: string
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
  const state = await extractCallbackState(input.rawRequest)
  // A SAML IdP-initiated POST may legitimately carry a `RelayState`
  // (Okta/Entra deep-link tokens), so "RelayState present" does NOT
  // imply "framework state envelope present". The envelope is only
  // real if it MAC-verifies. When there is no verifiable envelope —
  // none at all, or a value that fails verification — first try
  // IdP-initiated (the only flowless path). Only if that is not a
  // clean candidate do we emit the original error/audit, unchanged
  // for every method that did not opt into `unsolicitedCallback`.
  const envelopeRes = state
    ? await verifyStateEnvelope(state, deps.stateKeys)
    : null
  if (envelopeRes === null || isErr(envelopeRes)) {
    const idp = await tryIdpInitiated(input, deps, url)
    if (idp) return idp
    if (!state) {
      return err(authError.invalidRequest("missing state parameter", "state"))
    }
    // State present but no valid envelope and not an IdP-init
    // candidate — the original tampered/expired-envelope behaviour.
    await safeAudit(deps, {
      kind: "flow_replay_attempt",
      tenantId: null,
      flowId: "unknown",
      timestamp: deps.clock(),
    })
    return err(
      authError.invalidRequest(
        envelopeRes && isErr(envelopeRes)
          ? envelopeRes.error.description
          : "invalid state",
        "state",
      ),
    )
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
    issuerUrl: input.issuerUrl,
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
          ...(flow.appNonce !== undefined ? { appNonce: flow.appNonce } : {}),
          ...(flow.claimsRequest !== undefined
            ? { claimsRequest: flow.claimsRequest }
            : {}),
          authTime: Math.floor(now / 1000),
          expiresAt: now + AUTH_CODE_TTL_MS,
        },
        AUTH_CODE_TTL_MS,
        { keyStore: deps.keyStore, tokenStore: deps.tokenStore },
      )
      if (isErr(saved)) return err(saved.error)
      await safeAudit(deps, {
        kind: "authorize_succeeded",
        tenantId: flow.tenantId,
        clientId: flow.clientId,
        methodId: flow.methodId,
        methodKind: flow.methodKind,
        flowId: flow.flowId,
        providerSubject: result.providerSubject,
        timestamp: now,
      })
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

/**
 * IdP-initiated (unsolicited) SAML SSO — SAML-AD7, the one carve-out
 * vs. OAuth/OIDC methods. There is no AuthnRequest, no MAC state
 * envelope, and no flow record, so none of `handleCallback`'s gates
 * apply. Returns `null` when this is **not** a clean IdP-init candidate
 * (so the caller emits the normal "missing state" error — the
 * conservative default); otherwise a final `CallbackOutput`.
 *
 * Trust chain (no flow to lean on):
 *   - the assertion itself is signature/issuer/audience/conditions
 *     verified by the method (`consumeAssertion`, IdP-init mode) plus
 *     explicit assertion-ID replay dedup;
 *   - the RP binding is NOT attacker-influenced — it comes from the
 *     method's `unsolicitedBinding` (operator config), and is then
 *     re-validated here against the tenant's registered client +
 *     redirect URIs (open-redirect defence-in-depth). `RelayState` is
 *     never interpreted as a redirect.
 */
async function tryIdpInitiated(
  input: HandleCallbackInput,
  deps: HandleCallbackDeps,
  url: URL,
): Promise<Result<CallbackOutput, AuthError> | null> {
  if (input.rawRequest.method !== "POST") return null
  if (!input.tenant) return null

  const segments = url.pathname.split("/").filter(Boolean)
  if (segments.length < 2 || segments[0] !== "cb") return null
  const methodId = segments[1]!

  const methodRes = await deps.methodCache.resolve(
    input.tenant.config,
    methodId,
  )
  if (isErr(methodRes)) return null
  const method = methodRes.value
  if (method.unsolicitedCallback !== true) return null

  // Derived from `issuerUrl`, not the inbound request URL: a path-mounted
  // deployment sees a proxy-stripped pathname, so rebuilding from `url`
  // would emit a callback URL missing the mount prefix.
  const { url: callbackUrl } = callbackTarget({
    issuerUrl: input.issuerUrl,
    methodId,
    callbackHost: url.host,
  })
  const dispatched = await dispatchMethod({
    method,
    route: "GET /callback",
    tenant: input.tenant,
    request: input.rawRequest,
    subPath: "/callback",
    flow: null,
    cookies: input.cookies,
    sessionStore: deps.sessionStore,
    issuerUrl: input.issuerUrl,
    dispatch: { state: "", callbackUrl, issuerUrl: input.issuerUrl },
  })
  if (isErr(dispatched)) return err(dispatched.error)

  const result = dispatched.value
  if (result.kind === "challenge") {
    return ok({
      kind: "challenge",
      response: result.response,
      setCookies: result.setCookies ?? [],
      ...(result.cache !== undefined ? { cache: result.cache } : {}),
    })
  }
  if (result.kind === "denied") {
    await safeAudit(deps, {
      kind: "authorize_failed",
      tenantId: input.tenant.id,
      clientId: "idp-initiated",
      methodId,
      methodKind: method.kind,
      flowId: "idp-initiated",
      reason: result.reason,
      timestamp: deps.clock(),
    })
    return ok({
      kind: "denied",
      reason: result.reason,
      setCookies: result.setCookies ?? [],
    })
  }
  if (result.kind === "error") return err(result.error)

  // success — must carry the operator-configured RP binding.
  const binding = result.unsolicitedBinding
  if (!binding) {
    return err(
      authError.internalError(
        `method "${methodId}" handled an unsolicited callback but returned ` +
          `no unsolicitedBinding`,
      ),
    )
  }
  // Open-redirect defence-in-depth: the binding is operator config, but
  // still validate it against the tenant's registered client exactly
  // as /authorize validates an RP's redirect_uri.
  const client = input.tenant.config.clients.find(
    (c) => c.id === binding.clientId,
  )
  if (!client) {
    return err(
      authError.invalidRequest(
        `IdP-initiated binding references unknown client "${binding.clientId}"`,
      ),
    )
  }
  if (!client.redirectUris.includes(binding.redirectUri)) {
    return err(
      authError.invalidRequest(
        `IdP-initiated redirect_uri "${binding.redirectUri}" is not ` +
          `registered for client "${binding.clientId}"`,
      ),
    )
  }

  const code = (deps.newCodeId ?? randomToken)()
  const now = deps.clock()
  const saved = await saveEncryptedCode(
    code,
    {
      tenantId: input.tenant.id,
      clientId: binding.clientId,
      appRedirectUri: binding.redirectUri,
      // No RP-supplied OAuth state in an unsolicited flow; RelayState
      // is opaque and intentionally NOT echoed as `state`.
      appState: null,
      scopes: binding.scopes,
      methodId,
      methodKind: method.kind,
      context: input.tenant.request.custom ?? null,
      providerSubject: result.providerSubject,
      properties: result.properties,
      authTime: Math.floor(now / 1000),
      expiresAt: now + AUTH_CODE_TTL_MS,
    },
    AUTH_CODE_TTL_MS,
    { keyStore: deps.keyStore, tokenStore: deps.tokenStore },
  )
  if (isErr(saved)) return err(saved.error)
  await safeAudit(deps, {
    kind: "authorize_succeeded",
    tenantId: input.tenant.id,
    clientId: binding.clientId,
    methodId,
    methodKind: method.kind,
    // Unsolicited: there is no FlowRecord, so no flowId to correlate on.
    flowId: "",
    providerSubject: result.providerSubject,
    timestamp: now,
  })
  return ok({
    kind: "issue-code",
    code,
    appRedirectUri: binding.redirectUri,
    appState: null,
  })
}

function normalizePath(p: string): string {
  return p.replace(/\/+$/, "")
}
