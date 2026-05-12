/**
 * `/revoke` endpoint logic (RFC 7009).
 *
 * Access tokens are stateless JWTs in this IdP; revocation has to wait
 * for natural expiry. `tokenTypeHint: "access_token"` resolves to a
 * no-op per RFC 7009 §2.2 (invalid hint is ignored).
 *
 * Refresh tokens are server-side state. RFC 7009 §2.2 requires the
 * authorization server to verify that the presented token was issued to
 * the authenticated client and refuse otherwise. We implement this via
 * `peekRefresh` (non-destructive) → ownership check → `consumeRefresh`
 * (destructive). The peek/consume race is benign: if a concurrent caller
 * consumes the token in between, our consume returns `invalid_grant`,
 * which RFC 7009 §2.2 says we treat as a successful no-op.
 *
 * Anonymous revoke (no `client_id`) is permitted only for tokens issued
 * to public clients. Confidential-client tokens MUST authenticate per
 * RFC 7009 §2.1.
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { TokenStore } from "../ports/token-store"
import type { AuthError } from "../types/error"
import { authError } from "../types/error"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { TenantId } from "../types/tenant"

import { verifyClientCredentials } from "./client-auth"

export type RevokeRequest = {
  token: string
  /** RFC 7009 hint: `"access_token"` or `"refresh_token"`. */
  tokenTypeHint?: "access_token" | "refresh_token"
  /** Optional — required when revoking a confidential client's token. */
  clientId?: string
  clientSecret?: string
}

export type RevokeDeps = {
  tokenStore: TokenStore
  configStore: ConfigStore
  auditLog?: AuditLog
  clock: () => number
}

/**
 * Revoke a single refresh token. Anonymous revokes are accepted for
 * public-client tokens; confidential-client tokens require valid
 * credentials.
 */
export async function revokeToken(
  req: RevokeRequest,
  deps: RevokeDeps,
): Promise<Result<void, AuthError>> {
  if (req.tokenTypeHint === "access_token") {
    return ok(undefined)
  }

  // RFC 7009 §2.2: unknown tokens are successful no-ops. Peek tells us
  // the token's owner without consuming so we can authenticate first.
  const peek = await deps.tokenStore.peekRefresh(req.token)
  if (isErr(peek)) {
    return ok(undefined)
  }
  const payload = peek.value

  // Load the issuing client so we can decide whether auth is required.
  const tenantCfg = await deps.configStore.getTenantConfig(payload.tenantId)
  if (isErr(tenantCfg)) {
    // Tenant evaporated. Treat as no-op — caller can't usefully retry.
    return ok(undefined)
  }
  const client = tenantCfg.value.clients.find((c) => c.id === payload.clientId)
  if (!client) {
    return ok(undefined)
  }

  // Confidential clients MUST authenticate per RFC 7009 §2.1.
  if (client.type === "confidential") {
    if (!req.clientId || !req.clientSecret) {
      return err(
        authError.invalidClient(
          "confidential client must authenticate to revoke its tokens",
        ),
      )
    }
  }

  // If a client_id was presented but it doesn't own the token, RFC 7009
  // §2.2 still wants a successful no-op response — surfacing
  // `invalid_grant` here would let a different client probe for token
  // existence. Audit the attempt so operators can spot abuse.
  if (req.clientId !== undefined && req.clientId !== payload.clientId) {
    await audit(deps, {
      kind: "custom",
      type: "revoke_wrong_client_attempt",
      tenantId: payload.tenantId,
      data: {
        presentedClientId: req.clientId,
        tokenClientId: payload.clientId,
        subjectId: payload.subjectId,
      },
      timestamp: deps.clock(),
    })
    return ok(undefined)
  }

  // Credentials presented by the owning client must validate. Anonymous
  // revoke of a public-client token is permitted.
  if (req.clientId !== undefined) {
    const authErr = await verifyClientCredentials(client, req.clientSecret)
    if (authErr) return err(authErr)
  }

  const consumed = await deps.tokenStore.consumeRefresh(req.token, {
    reuseWindowMs: 0,
  })
  if (isErr(consumed)) {
    return ok(undefined)
  }
  await audit(deps, {
    kind: "token_revoked",
    tenantId: payload.tenantId,
    clientId: payload.clientId,
    subjectId: payload.subjectId,
    family: payload.family,
    reason: "client_revoke",
    timestamp: deps.clock(),
  })
  return ok(undefined)
}

/**
 * Revoke every refresh token for a `(tenantId, subjectId)` pair and emit
 * a `token_revoked` audit event with `reason: "subject_revoke"`.
 *
 * Public primitive exposed for host-driven "log me out of all devices"
 * flows. Not called from the reuse-detection path — that stays at
 * family-scope per OAuth 2.0 Security BCP §4.13.2 (revoking sibling
 * families would punish legitimate other-device sessions sharing the
 * same subject). See ARCHITECTURE.md §"Reuse detection scope".
 */
export async function revokeAllForSubject(
  tenantId: TenantId,
  subjectId: string,
  deps: { tokenStore: TokenStore; auditLog?: AuditLog; clock: () => number },
): Promise<Result<void, AuthError>> {
  const res = await deps.tokenStore.revokeBySubject(tenantId, subjectId)
  if (isErr(res)) return err(res.error)
  await audit(deps, {
    kind: "token_revoked",
    tenantId,
    clientId: null,
    subjectId,
    reason: "subject_revoke",
    timestamp: deps.clock(),
  })
  return ok(undefined)
}

async function audit(
  deps: { auditLog?: AuditLog },
  event: Parameters<AuditLog["log"]>[0],
): Promise<void> {
  if (!deps.auditLog) return
  try {
    await deps.auditLog.log(event)
  } catch {
    /* swallow */
  }
}
