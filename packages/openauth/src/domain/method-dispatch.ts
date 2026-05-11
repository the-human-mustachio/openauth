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
} from "../types/method"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantContext } from "../types/tenant"

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
    subPath: input.subPath,
    tenant: input.tenant,
    flow: input.flow,
    methodState: input.flow?.methodState ?? null,
    cookies: input.cookies,
    dispatch: input.dispatch,
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
