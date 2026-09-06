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
import type { LogoutEventInput, LogoutHookResult } from "../types/idp"
import type {
  AuthMethod,
  CachePolicy,
  MethodDispatchData,
  MethodResult,
  SetCookie,
} from "../types/method"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantContext } from "../types/tenant"

import { safeAudit } from "./audit"
import { AUTH_CODE_TTL_MS } from "./authorize"
import { randomToken } from "./crypto"
import { MethodCache } from "./method-cache"
import { dispatchMethod, type RouteKey } from "./method-dispatch"
import { revokeAllForSubject } from "./revoke"
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
  /**
   * Issuer URL — passed to the method so it can emit mount-prefixed URLs
   * (a re-rendered form action, say). The inbound request URL cannot
   * supply this: a proxy has already stripped the mount prefix from it.
   */
  issuerUrl: string
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
    issuerUrl: input.issuerUrl,
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
          ...(final.claimsRequest !== undefined
            ? { claimsRequest: final.claimsRequest }
            : {}),
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

/**
 * Anonymous public method route — the fourth, deliberately narrow,
 * pipeline. Used only for route keys a method explicitly lists in
 * `AuthMethod.publicRoutes` (today: SAML SP `GET /metadata`). No flow
 * cookie, no flow record, no `SessionStore` read: the handler is a pure
 * function of `tenant` + `dispatch` + captured config.
 *
 * Security: this re-checks `publicRoutes` membership against the
 * resolved method. The HTTP layer also checks before routing here, but
 * a domain function guarding a no-auth path must not trust its caller —
 * the gate is enforced here too, fail-closed.
 *
 * Only `challenge` (the metadata document) and `denied` are sensible
 * outcomes; `success` from a flowless route is a programming error
 * (there is no flow to consume into an auth code) and surfaces as an
 * internal error rather than silently authenticating.
 */
export type HandlePublicMethodRouteInput = {
  rawRequest: Request
  tenant: TenantContext
  /** Pre-resolved by the HTTP layer (it needed it to detect the public route). */
  method: AuthMethod
  route: RouteKey
  subPath: string
  /** Issuer/callback context so the handler can derive stable URLs. */
  dispatch: MethodDispatchData
}

export type HandlePublicMethodRouteDeps = {
  sessionStore: SessionStore
  /**
   * Required for the upstream-logout path: when a public route returns a
   * `challenge` carrying `logout`, the framework runs
   * `revokeAllForSubject` for the host-named subject. Anonymous read-only
   * public routes (`/metadata`-style) never touch this.
   */
  tokenStore: TokenStore
  clock: () => number
  auditLog?: AuditLog
  /**
   * See `IdPOptions.onLogout`. Absent ⇒ the framework still verifies +
   * acknowledges the logout and audits it, but revokes nothing (it
   * cannot resolve the upstream id to a subject without the host).
   */
  onLogout?: (
    input: LogoutEventInput,
  ) => Promise<LogoutHookResult> | LogoutHookResult
}

export type PublicMethodRouteOutput =
  | { kind: "challenge"; response: Response; cache?: CachePolicy }
  | { kind: "denied"; reason: string }

export async function handlePublicMethodRoute(
  input: HandlePublicMethodRouteInput,
  deps: HandlePublicMethodRouteDeps,
): Promise<Result<PublicMethodRouteOutput, AuthError>> {
  if (!input.method.publicRoutes?.includes(input.route)) {
    return err(
      authError.invalidRequest(
        `route "${input.route}" is not public on method "${input.method.id}"`,
        "path",
      ),
    )
  }

  const dispatched = await dispatchMethod({
    method: input.method,
    route: input.route,
    tenant: input.tenant,
    request: input.rawRequest,
    subPath: input.subPath,
    flow: null,
    cookies: new Map(),
    sessionStore: deps.sessionStore,
    issuerUrl: input.dispatch.issuerUrl,
    dispatch: input.dispatch,
  })
  if (isErr(dispatched)) return err(dispatched.error)

  const r = dispatched.value
  switch (r.kind) {
    case "challenge": {
      // A verified upstream logout (SAML front-channel SLS): the method
      // proved authenticity and built the `LogoutResponse`; the
      // privileged side effect (host teardown + token revocation) runs
      // here, where the ports live. Fail closed — if the side effect
      // errors we do NOT hand back a `LogoutResponse` that would tell
      // the IdP the user is logged out when they may not be.
      if (r.logout) {
        const sideEffect = await runUpstreamLogout(input, deps, r.logout)
        if (isErr(sideEffect)) return err(sideEffect.error)
      }
      return ok({
        kind: "challenge",
        response: r.response,
        ...(r.cache !== undefined ? { cache: r.cache } : {}),
      })
    }
    case "denied":
      return ok({ kind: "denied", reason: r.reason })
    case "success":
      return err(
        authError.internalError(
          `public route "${input.route}" on method "${input.method.id}" ` +
            `returned success — a flowless route cannot authenticate`,
        ),
      )
    case "error":
      return err(r.error)
  }
}

/**
 * Run the privileged side effect for a verified upstream logout: fire
 * the host's `onLogout` hook, then — if the host named a subject —
 * revoke that subject's library-issued tokens via the same
 * `revokeAllForSubject` primitive `/end_session` uses. Always emits a
 * `session_logout` audit event (`via: "upstream_slo"`).
 *
 * The library cannot map the upstream `nameId` to an OIDC subject
 * itself (that mapping lives in the host's `success` callback), so
 * revocation is host-directed by design. A throwing hook or a failed
 * revoke fails closed (`internal_error`) — the caller then withholds
 * the `LogoutResponse`.
 */
async function runUpstreamLogout(
  input: HandlePublicMethodRouteInput,
  deps: HandlePublicMethodRouteDeps,
  logout: { nameId?: string; sessionIndex?: string },
): Promise<Result<void, AuthError>> {
  let hookResult: LogoutHookResult = undefined
  if (deps.onLogout) {
    const evt: LogoutEventInput = {
      tenant: input.tenant,
      methodId: input.method.id,
      methodKind: input.method.kind,
      reason: "upstream_slo",
      ...(logout.nameId !== undefined ? { nameId: logout.nameId } : {}),
      ...(logout.sessionIndex !== undefined
        ? { sessionIndex: logout.sessionIndex }
        : {}),
    }
    try {
      hookResult = await deps.onLogout(evt)
    } catch (e) {
      return err(
        authError.internalError(
          `onLogout hook threw during upstream Single Logout for method ` +
            `"${input.method.id}"`,
          e,
        ),
      )
    }
  }

  const revokeSubject =
    hookResult && typeof hookResult === "object"
      ? hookResult.revokeSubject
      : undefined

  if (revokeSubject) {
    const revoked = await revokeAllForSubject(input.tenant.id, revokeSubject, {
      tokenStore: deps.tokenStore,
      ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
      clock: deps.clock,
    })
    if (isErr(revoked)) return err(revoked.error)
  }

  await safeAudit(deps, {
    kind: "session_logout",
    tenantId: input.tenant.id,
    via: "upstream_slo",
    methodId: input.method.id,
    methodKind: input.method.kind,
    ...(revokeSubject ? { subjectId: revokeSubject } : {}),
    timestamp: deps.clock(),
  })
  return ok(undefined)
}
