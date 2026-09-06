/**
 * Method dispatch — invoke a method's route handler, then enforce the
 * `saveMethodState` durability contract.
 *
 * Per `ARCHITECTURE.md`: when a method handler returns
 * `{ kind: "challenge", saveMethodState }`, the framework MUST persist
 * `methodState` via `SessionStore.updateFlowMethodState` **before**
 * surfacing the response. Centralizing that here keeps the
 * happens-before contract uniform across every call site.
 */
import type { SessionStore } from "../ports/session-store"
import { authError, type AuthError } from "../types/error"
import type { FlowRecord } from "../types/flow"
import type {
  AuthMethod,
  MethodContext,
  MethodDispatchData,
  MethodResult,
  MethodScratch,
} from "../types/method"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantContext, TenantId } from "../types/tenant"

export type RouteKey = `${"GET" | "POST"} ${string}`

export type DispatchInput = {
  method: AuthMethod
  route: RouteKey
  tenant: TenantContext
  request: Request
  subPath: string
  flow: FlowRecord | null
  cookies: ReadonlyMap<string, string>
  sessionStore: SessionStore
  /**
   * Issuer URL of this IdP. Always required — unlike `dispatch`, methods
   * need it on every route to emit mount-prefixed URLs of their own.
   */
  issuerUrl: string
  /** Populated at `GET /authorize`; null on callbacks. */
  dispatch: MethodDispatchData | null
}

/**
 * Invoke the named route on the method. If the result is a challenge with
 * `saveMethodState`, persist it to `SessionStore` and only then return.
 * The framework owns this happens-before guarantee so methods cannot
 * accidentally surface a redirect before the upstream verifier is durable.
 */
export async function dispatchMethod(
  input: DispatchInput,
): Promise<Result<MethodResult<unknown, unknown>, AuthError>> {
  const handler = input.method.routes[input.route]
  if (!handler) {
    return err(
      authError.invalidRequest(
        `method "${input.method.id}" has no handler for route "${input.route}"`,
      ),
    )
  }

  const ctx: MethodContext<unknown> = {
    request: input.request,
    issuerUrl: input.issuerUrl,
    subPath: input.subPath,
    tenant: input.tenant,
    flow: input.flow,
    methodState: input.flow?.methodState ?? null,
    cookies: input.cookies,
    dispatch: input.dispatch,
    methodScratch: buildMethodScratch(
      input.sessionStore,
      input.tenant.id,
      input.method.id,
    ),
  }

  let result: MethodResult<unknown, unknown>
  try {
    result = await handler(ctx)
  } catch (e) {
    return err(
      authError.serverError(
        `method "${input.method.id}" handler threw on route "${input.route}"`,
        e,
      ),
    )
  }

  if (result.kind === "challenge" && result.saveMethodState !== undefined) {
    if (!input.flow) {
      return err(
        authError.internalError(
          `method "${input.method.id}" returned saveMethodState without an active flow`,
        ),
      )
    }
    const persisted = await input.sessionStore.updateFlowMethodState(
      input.flow.flowId,
      result.saveMethodState,
    )
    if (isErr(persisted)) return err(persisted.error)
  }

  return ok(result)
}

/**
 * Construct the scoped `MethodScratch` handed to a method handler. Keys
 * are namespaced `scratch:<tenantId>:<methodId>:<userKey>` so a method
 * instance can never read or clobber another instance's data — even
 * across tenants on a shared store.
 *
 * When the underlying `SessionStore` doesn't implement
 * `saveScratch` / `readScratch` / `deleteScratch`, every operation
 * returns `unsupportedAdapter` so methods can surface a clean error
 * rather than silently no-op.
 */
function buildMethodScratch(
  store: SessionStore,
  tenantId: TenantId,
  methodId: string,
): MethodScratch {
  const prefix = `scratch:${tenantId}:${methodId}:`
  const scope = (key: string): string => `${prefix}${key}`
  const unsupported = (op: string): AuthError =>
    authError.internalError(
      `SessionStore does not implement ${op}; methodScratch is unavailable on this adapter`,
    )

  return {
    put: async (key, value, ttlMs) => {
      if (!store.saveScratch) return err(unsupported("saveScratch"))
      if (ttlMs <= 0) {
        return err(
          authError.internalError(
            `methodScratch.put: ttlMs must be positive, got ${ttlMs}`,
          ),
        )
      }
      return store.saveScratch(scope(key), value, ttlMs)
    },
    get: async (key) => {
      if (!store.readScratch) return err(unsupported("readScratch"))
      return store.readScratch(scope(key))
    },
    delete: async (key) => {
      if (!store.deleteScratch) return err(unsupported("deleteScratch"))
      return store.deleteScratch(scope(key))
    },
  }
}
