/**
 * `/token` logic for `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
 * (RFC 8693).
 *
 * Scope: **audience-switch / impersonation only.** A subject who holds an
 * access token for tenant A can present it here to receive a fresh
 * access + refresh pair scoped to tenant B (the `audience` parameter).
 * Delegation (`actor_token`) is rejected at the HTTP layer.
 *
 * Flow:
 *   1. Verify the `subject_token` JWT against the IdP's own signing keys.
 *      Expired / wrong-issuer / bad-sig tokens fail with `invalid_grant`
 *      (per RFC 8693 §2.4).
 *   2. Refuse if the host hasn't configured `exchangeAudience` — return
 *      `unsupported_grant_type` for graceful degradation.
 *   3. Narrow scope if the caller requested a subset.
 *   4. Call `exchangeAudience(currentClaim, request)`. The host returns
 *      either the SubjectClaim that should anchor the new tokens at the
 *      target tenant, or an `AuthError` (typically `invalid_target`).
 *   5. Load the target tenant config via `ConfigStore.getTenantConfig`.
 *      This validates that the audience is a real partition.
 *   6. Mint a fresh access + refresh pair with `tid = audience` and a
 *      brand-new refresh family. The previous family lives untouched.
 *   7. Audit `token_exchanged`.
 *
 * Notes:
 *   - The new tokens' `clientId` is the **authenticated** client (the
 *     one doing the exchange), not the original audience of the
 *     subject_token. Hosts that need a different client must register
 *     one in the target tenant.
 *   - `methodId` / `methodKind` are preserved from the subject_token so
 *     the audit trail still names the original authentication method.
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { TokenStore } from "../ports/token-store"
import { authError, type AuthError } from "../types/error"
import type { ExchangeAudience } from "../types/idp"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { SubjectClaim } from "../types/subject"
import type { ClientConfig, TenantContext, TenantId } from "../types/tenant"
import type {
  AccessTokenClaims,
  TokenResponse,
} from "../types/token"

import { verifyClientCredentials } from "./client-auth"
import { randomId } from "./crypto"
import { verifyAccessToken } from "./jwt"
import { mintTokens } from "./token"

export type TokenExchangeRequest = {
  grantType: "urn:ietf:params:oauth:grant-type:token-exchange"
  subjectToken: string
  audience: string
  /** Confidential clients authenticate. Public clients use the subject_token alone. */
  clientId?: string
  clientSecret?: string
  /** Optional subset of subject_token scopes. */
  scope?: string
}

export type TokenExchangeResponse = TokenResponse & {
  /** RFC 8693 §2.2.1. Always `access_token` for this grant. */
  issued_token_type: "urn:ietf:params:oauth:token-type:access_token"
}

export type ExchangeTokenDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  auditLog?: AuditLog
  exchangeAudience?: ExchangeAudience
  issuerUrl: string
  clock: () => number
  newRefreshFamily?: () => string
}

export async function exchangeToken(
  req: TokenExchangeRequest,
  deps: ExchangeTokenDeps,
): Promise<Result<TokenExchangeResponse, AuthError>> {
  // 1. Graceful degradation: refuse cleanly if not configured.
  if (!deps.exchangeAudience) {
    return err(
      authError.unsupportedGrantType(
        "token-exchange is not configured on this IdP",
      ),
    )
  }

  // 2. Verify the subject_token.
  const keysRes = await deps.keyStore.signingKeys()
  if (isErr(keysRes)) return err(keysRes.error)
  let subjectClaims: AccessTokenClaims
  try {
    subjectClaims = await verifyAccessToken(req.subjectToken, keysRes.value, {
      issuer: deps.issuerUrl,
    })
  } catch (e) {
    return err(
      authError.invalidGrant(
        `subject_token verification failed: ${
          e instanceof Error ? e.message : "unknown"
        }`,
      ),
    )
  }
  if (!subjectClaims.claim) {
    return err(
      authError.invalidGrant(
        "subject_token does not carry a SubjectClaim — was it issued by this IdP?",
      ),
    )
  }

  // 3. Load the issuing tenant + client so we can authenticate the caller.
  const fromTenantId = subjectClaims.tid
  const fromTenantCfg = await deps.configStore.getTenantConfig(fromTenantId)
  if (isErr(fromTenantCfg)) return err(fromTenantCfg.error)
  // The client doing the exchange — defaults to the subject_token's `aud`
  // when not presented (public-client case).
  const callerClientId = req.clientId ?? subjectClaims.aud
  const callerClient = fromTenantCfg.value.clients.find(
    (c: ClientConfig) => c.id === callerClientId,
  )
  if (!callerClient) {
    return err(
      authError.invalidClient(`unknown client "${callerClientId}"`),
    )
  }
  // Same client-auth rules as auth_code / refresh: confidential clients
  // MUST authenticate; public clients MUST NOT present a secret.
  const authErr = await verifyClientCredentials(callerClient, req.clientSecret)
  if (authErr) return err(authErr)

  // 4. Scope subset check (RFC 8693 §2.1 — `scope` MAY be requested).
  const subjectScopes = (subjectClaims.scope ?? "")
    .split(" ")
    .filter((s) => s.length > 0)
  const requestedScopes = req.scope
    ? req.scope.split(" ").filter((s) => s.length > 0)
    : subjectScopes
  for (const s of requestedScopes) {
    if (!subjectScopes.includes(s)) {
      return err(
        authError.invalidScope(
          `requested scope "${s}" not granted by subject_token`,
        ),
      )
    }
  }

  // 5. Host decision — does the subject get to access `audience`?
  const audienceClaim = await deps.exchangeAudience(
    subjectClaims.claim,
    {
      audience: req.audience,
      ...(req.scope !== undefined ? { requestedScopes } : {}),
      clientId: callerClient.id,
      fromTenantId,
    },
  )
  // The hook may return either a SubjectClaim (success) or an
  // AuthError (rejection). Distinguish by checking for the `code`
  // discriminator — AuthError is a closed taxonomy, all variants have
  // `code: string`.
  if (
    typeof (audienceClaim as { code?: unknown }).code === "string" &&
    typeof (audienceClaim as { description?: unknown }).description === "string"
  ) {
    return err(audienceClaim as AuthError)
  }
  const newClaim = audienceClaim as SubjectClaim

  // 6. Load the target tenant config so mintTokens has a TenantContext.
  const targetTenantId = req.audience as TenantId
  const targetTenantCfg = await deps.configStore.getTenantConfig(targetTenantId)
  if (isErr(targetTenantCfg)) return err(targetTenantCfg.error)
  // Verify the calling client exists at the target tenant — otherwise
  // the issued token's `aud` would name a client the target tenant
  // doesn't know about.
  const targetClient = targetTenantCfg.value.clients.find(
    (c: ClientConfig) => c.id === callerClient.id,
  )
  if (!targetClient) {
    return err(
      authError.invalidTarget(
        `client "${callerClient.id}" is not registered in target tenant "${targetTenantId}"`,
      ),
    )
  }

  // 7. Mint. Fresh family — previous family is untouched.
  const targetTenant: TenantContext = {
    id: targetTenantId,
    config: targetTenantCfg.value,
    request: { raw: new Request("about:blank"), custom: {} },
  }
  const minted = await mintTokens({
    tenant: targetTenant,
    claim: newClaim,
    payload: {
      tenantId: targetTenantId,
      clientId: callerClient.id,
      // Preserve provenance — operators can trace exchanged tokens back
      // to the originating method through the audit chain.
      methodId: subjectClaims.mid ?? "token_exchange",
      methodKind: subjectClaims.mkind ?? "token_exchange",
      scopes: requestedScopes,
      ...(subjectClaims.aud !== undefined && subjectClaims.aud !== callerClient.id
        ? { audience: subjectClaims.aud }
        : {}),
    },
    family: (deps.newRefreshFamily ?? randomId)(),
    deps,
  })
  if (isErr(minted)) return err(minted.error)

  // 8. Audit. mintTokens already emits `token_issued`; the additional
  // `token_exchanged` event records the cross-tenant context.
  if (deps.auditLog) {
    try {
      await deps.auditLog.log({
        kind: "token_exchanged",
        tenantId: targetTenantId,
        fromTenantId,
        clientId: callerClient.id,
        subjectId: subjectClaims.sub,
        family: "exchanged",
        timestamp: deps.clock(),
      })
    } catch {
      /* swallow — auditing is best-effort */
    }
  }

  return ok({
    ...minted.value,
    issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
  })
}
