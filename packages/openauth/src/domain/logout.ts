/**
 * `/end_session` endpoint logic — OIDC RP-Initiated Logout 1.0.
 *
 * The OP validates the optional `id_token_hint`, validates the optional
 * `post_logout_redirect_uri` against the client's registered list,
 * revokes the subject's refresh tokens (when a subject is identified),
 * and either redirects the user-agent back to the RP with `state` echoed
 * or returns a generic "logged out" acknowledgement.
 *
 * Per §2:
 *  - `id_token_hint` (RECOMMENDED): a previously-issued id_token. The
 *    OP MUST verify the signature; expiry MAY be tolerated because
 *    logout commonly follows token expiry. We accept expired hints but
 *    enforce signature + issuer.
 *  - `client_id` (OPTIONAL): when both this and `id_token_hint` are
 *    present, the OP MUST verify the client_id matches the hint's `aud`.
 *  - `post_logout_redirect_uri` (OPTIONAL): MUST be exact-match against
 *    the resolved client's `postLogoutRedirectUris`. If the URI is not
 *    registered, the OP MUST NOT redirect — surface a non-redirecting
 *    error instead, otherwise the endpoint becomes an open redirector.
 *  - `state` (OPTIONAL): echoed back in the redirect.
 *
 * Front-channel / back-channel logout (RP notification of OP-initiated
 * logout) is out of scope for this minimal endpoint. Hosts that need it
 * can layer their own notification fan-out on top of `session_logout`
 * audit events.
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { TokenStore } from "../ports/token-store"
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { ClientConfig, TenantContext } from "../types/tenant"

import { safeAudit } from "./audit"
import { verifyIdToken } from "./jwt"
import { revokeAllForSubject } from "./revoke"

export type EndSessionRequest = {
  idTokenHint?: string
  clientId?: string
  postLogoutRedirectUri?: string
  state?: string
}

export type EndSessionDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  auditLog?: AuditLog
  issuerUrl: string
  clock: () => number
}

export type EndSessionOutput =
  /** Redirect the user-agent back to the RP. */
  | { kind: "redirect"; url: string }
  /**
   * No `post_logout_redirect_uri` was supplied (or it wasn't registered).
   * Caller should render a minimal "logged out" page or return 200.
   */
  | { kind: "ok"; subjectId?: string }

/**
 * Process an `/end_session` request and return an outcome the HTTP
 * adapter can translate into a `Response`. Pure domain — no Hono types,
 * no `Response` construction here.
 */
export async function endSession(
  req: EndSessionRequest,
  tenant: TenantContext,
  deps: EndSessionDeps,
): Promise<Result<EndSessionOutput, AuthError>> {
  // 1. Verify the id_token_hint (if present). Tolerate expiry per §2.
  let hintSubject: string | undefined
  let hintAud: string | undefined
  if (req.idTokenHint) {
    const keysRes = await deps.keyStore.signingKeys()
    if (isErr(keysRes)) return err(keysRes.error)
    try {
      const claims = await verifyIdToken(req.idTokenHint, keysRes.value, {
        issuer: deps.issuerUrl,
        acceptExpired: true,
      })
      hintSubject = claims.sub
      hintAud = claims.aud
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e)
      return err(
        authError.invalidRequest(
          `id_token_hint failed signature/issuer verification: ${reason}`,
          "id_token_hint",
        ),
      )
    }
  }

  // 2. If both client_id and id_token_hint are present, they MUST agree
  //    (§2). Disagreement is `invalid_request` — never a redirect.
  if (req.clientId && hintAud && req.clientId !== hintAud) {
    return err(
      authError.invalidRequest(
        "client_id does not match id_token_hint.aud",
        "client_id",
      ),
    )
  }

  // 3. Resolve the client for redirect-URI validation. Prefer explicit
  //    client_id, fall back to the hint's aud.
  const resolvedClientId = req.clientId ?? hintAud
  let client: ClientConfig | undefined
  if (resolvedClientId) {
    client = tenant.config.clients.find((c) => c.id === resolvedClientId)
    if (!client) {
      return err(
        authError.invalidRequest(
          `unknown client "${resolvedClientId}"`,
          "client_id",
        ),
      )
    }
  }

  // 4. Validate post_logout_redirect_uri. MUST be exact-match against
  //    the client's registered list (§2). No client → no validatable URI.
  if (req.postLogoutRedirectUri) {
    if (!client) {
      return err(
        authError.invalidRequest(
          "post_logout_redirect_uri requires identifying the client via client_id or id_token_hint",
          "post_logout_redirect_uri",
        ),
      )
    }
    const registered = client.postLogoutRedirectUris ?? []
    if (!registered.includes(req.postLogoutRedirectUri)) {
      return err(
        authError.invalidRequest(
          "post_logout_redirect_uri is not registered for this client",
          "post_logout_redirect_uri",
        ),
      )
    }
  }

  // 5. Revoke the subject's tokens. Only possible when an id_token_hint
  //    identified a subject. Without a hint, /end_session is essentially
  //    a session-cookie clear (which the framework doesn't yet own); we
  //    still return a successful redirect/ok so RPs can complete UX.
  if (hintSubject) {
    const revoked = await revokeAllForSubject(tenant.id, hintSubject, {
      tokenStore: deps.tokenStore,
      ...(deps.auditLog ? { auditLog: deps.auditLog } : {}),
      clock: deps.clock,
    })
    if (isErr(revoked)) return err(revoked.error)
  }

  await safeAudit(deps, {
    kind: "session_logout",
    tenantId: tenant.id,
    ...(resolvedClientId ? { clientId: resolvedClientId } : {}),
    ...(hintSubject ? { subjectId: hintSubject } : {}),
    timestamp: deps.clock(),
  })

  // 6. Build the redirect or signal "ok" for the caller to render.
  if (req.postLogoutRedirectUri) {
    const url = new URL(req.postLogoutRedirectUri)
    if (req.state !== undefined) url.searchParams.set("state", req.state)
    return ok({ kind: "redirect", url: url.toString() })
  }
  return ok({
    kind: "ok",
    ...(hintSubject ? { subjectId: hintSubject } : {}),
  })
}
