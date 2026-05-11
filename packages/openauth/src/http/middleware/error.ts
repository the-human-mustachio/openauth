/**
 * Global error middleware. Catches thrown values and serializes them as
 * OAuth-compliant responses. Inside handlers we route through `Result<T,
 * AuthError>` instead — this is the last-resort net for unexpected throws.
 */
import type { MiddlewareHandler } from "hono"

import { authError } from "../../types/error"

import type { HttpDeps, HttpEnv } from "../context"
import { tokenEndpointErrorResponse } from "../errors"

export function errorMiddleware(
  _deps: HttpDeps,
): MiddlewareHandler<HttpEnv> {
  return async (_c, next) => {
    try {
      await next()
    } catch (e) {
      return tokenEndpointErrorResponse(
        authError.serverError(
          e instanceof Error ? e.message : "unexpected error",
          e,
        ),
      )
    }
  }
}
