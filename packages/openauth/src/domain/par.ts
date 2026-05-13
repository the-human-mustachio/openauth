/**
 * Pushed Authorization Requests (RFC 9126).
 *
 * The RP submits the full `/authorize` parameter set to `POST /par` along
 * with its client credentials. The OP authenticates the client, stores
 * the payload under an opaque `request_uri`, and returns it with an
 * `expires_in`. The RP then redirects the user-agent to
 * `GET /authorize?client_id=...&request_uri=...` and the OP rehydrates
 * the original parameter set.
 *
 * Per RFC 9126 §3:
 *  - Response is HTTP 201 with `application/json` body
 *    `{request_uri, expires_in}`.
 *  - `request_uri` MUST be of the form
 *    `urn:ietf:params:oauth:request_uri:<opaque>` (§2.2).
 *  - Default TTL is 60 seconds — same as auth-code TTL.
 *
 * Per RFC 9126 §4:
 *  - At `/authorize`, `request_uri` is one-shot — consumed and discarded
 *    on first use.
 *  - Parameters in the PAR record take precedence; additional `/authorize`
 *    parameters MAY be merged but MUST NOT contradict (we strictly use
 *    the PAR'd set and ignore any additional ones except `client_id`).
 *
 * Client authentication (§2):
 *  - Public clients: `client_id` only.
 *  - Confidential clients: `client_id` + `client_secret` (Basic or form).
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { SessionStore } from "../ports/session-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantContext } from "../types/tenant"

import { verifyClientCredentials } from "./client-auth"
import { randomToken } from "./crypto"

export const PAR_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"
export const DEFAULT_PAR_TTL_MS = 60 * 1000

export type ParRequest = {
  clientId: string
  /** Confidential-client secret. */
  clientSecret?: string
  /** Raw `/authorize` parameter record, posted by the RP. */
  params: Record<string, string>
}

export type ParResponse = {
  request_uri: string
  expires_in: number
}

export type ParDeps = {
  configStore: ConfigStore
  sessionStore: SessionStore
  auditLog?: AuditLog
  clock: () => number
  /** Test override. */
  newRequestUriSuffix?: () => string
  ttlMs?: number
}

/**
 * Process a `POST /par` request. Authenticates the client, validates the
 * `client_id` consistency, and persists the parameter set.
 */
export async function pushAuthorizationRequest(
  req: ParRequest,
  tenant: TenantContext,
  deps: ParDeps,
): Promise<Result<ParResponse, AuthError>> {
  if (!deps.sessionStore.savePar || !deps.sessionStore.consumePar) {
    return err(
      authError.invalidRequest(
        "session adapter does not implement PAR storage",
      ),
    )
  }

  // 1. Client authentication. The `client_id` in the body must match the
  //    authenticating client.
  const client = tenant.config.clients.find((c) => c.id === req.clientId)
  if (!client) {
    return err(authError.invalidClient(`unknown client "${req.clientId}"`))
  }
  if (client.type === "confidential") {
    const authErr = await verifyClientCredentials(client, req.clientSecret)
    if (authErr) return err(authErr)
  } else if (req.clientSecret !== undefined) {
    return err(
      authError.invalidClient(
        "public client must not present client_secret",
      ),
    )
  }

  // 2. Sanity-check the body: client_id in body must match — the RFC
  //    requires it (§2). RP shouldn't be authenticating one client and
  //    pushing params for a different one.
  if (req.params.client_id && req.params.client_id !== req.clientId) {
    return err(
      authError.invalidRequest(
        "client_id in body conflicts with authenticated client",
        "client_id",
      ),
    )
  }
  // RFC 9126 §2.1: `request_uri` MUST NOT appear in a PAR request body.
  if ("request_uri" in req.params) {
    return err(
      authError.invalidRequest(
        "request_uri MUST NOT be present in a PAR request",
        "request_uri",
      ),
    )
  }

  // 3. Mint request_uri + persist.
  const suffix = (deps.newRequestUriSuffix ?? randomToken)()
  const requestUri = PAR_URI_PREFIX + suffix
  const ttl = deps.ttlMs ?? DEFAULT_PAR_TTL_MS
  const now = deps.clock()
  const saved = await deps.sessionStore.savePar(
    requestUri,
    {
      requestUri,
      params: { ...req.params, client_id: req.clientId },
      clientId: req.clientId,
      issuedAt: now,
      expiresAt: now + ttl,
    },
    ttl,
  )
  if (isErr(saved)) return err(saved.error)

  return ok({
    request_uri: requestUri,
    expires_in: Math.floor(ttl / 1000),
  })
}
