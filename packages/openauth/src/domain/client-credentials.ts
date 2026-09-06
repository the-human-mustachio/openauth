/**
 * `/token` endpoint logic for `grant_type=client_credentials` (RFC 6749 §4.4).
 *
 * Steps:
 *   1. Authenticate the client. Must be confidential and must declare
 *      `client_credentials` in `grantTypes`.
 *   2. Resolve the tenant's m2m method. The plan models m2m as a method
 *      with a `client` fn and no routes; we look for the unique
 *      `type === "m2m"` instance on the tenant. Zero or multiple → error.
 *   3. Call `method.client({ clientID, clientSecret, params })`. On
 *      success the method returns the `P` properties it would have
 *      emitted on a `success` MethodResult.
 *   4. Invoke the user's `success` callback to mint the subject claim
 *      with `methodKind = method.kind`, `methodId = method.id`.
 *   5. `mintTokens` — access token only (no refresh per §4.4.3).
 *
 * The framework rejects requests presenting `scope` beyond what
 * `ClientConfig.scopes` allows.
 */
import type { AuditLog } from "../ports/audit-log"
import type { ConfigStore } from "../ports/config-store"
import type { KeyStore } from "../ports/key-store"
import type { TokenStore } from "../ports/token-store"
import { authError, type AuthError } from "../types/error"
import type { PersistUpstreamTokens, SuccessMapInput } from "../types/idp"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { SubjectClaim, SubjectSchema } from "../types/subject"
import type { TenantContext, TenantId } from "../types/tenant"
import type { TokenResponse } from "../types/token"

import { verifyClientCredentials } from "./client-auth"
import { randomId } from "./crypto"
import { mintTokens } from "./token"
import { MethodCache } from "./method-cache"
import { safeAudit } from "./audit"
import { validateSubjectClaim } from "./subject"

export type ClientCredentialsRequest = {
  grantType: "client_credentials"
  clientId: string
  clientSecret: string
  scope?: string
  /** Extra params (audience, resource, etc.). Forwarded to `method.client`. */
  params?: Record<string, string>
}

export type ClientCredentialsDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  auditLog?: AuditLog
  methodCache: MethodCache
  success: (input: SuccessMapInput) => Promise<SubjectClaim>
  /** Host-declared subject schemas; the claim is validated against them. */
  subjects: SubjectSchema
  persistUpstreamTokens?: PersistUpstreamTokens
  issuerUrl: string
  clock: () => number
  newRefreshFamily?: () => string
  /** See `IdPOptions.customScopeClaims`. Forwarded to `mintTokens`. */
  customScopeClaims?: Record<string, ReadonlyArray<string>>
}

export async function clientCredentialsGrant(
  req: ClientCredentialsRequest,
  deps: ClientCredentialsDeps,
  tenantId: TenantId,
): Promise<Result<TokenResponse, AuthError>> {
  // 1. Tenant + client lookup.
  const tenantCfg = await deps.configStore.getTenantConfig(tenantId)
  if (isErr(tenantCfg)) return err(tenantCfg.error)
  const client = tenantCfg.value.clients.find((c) => c.id === req.clientId)
  if (!client) {
    return err(authError.invalidClient(`unknown client "${req.clientId}"`))
  }
  if (client.type !== "confidential") {
    return err(
      authError.invalidClient(
        "client_credentials requires confidential client",
      ),
    )
  }
  if (!client.grantTypes.includes("client_credentials")) {
    return err(
      authError.unauthorizedClient(
        `client "${client.id}" is not authorized for client_credentials`,
      ),
    )
  }
  const authErr = await verifyClientCredentials(client, req.clientSecret)
  if (authErr) return err(authErr)

  // 2. Scope validation.
  const requestedScopes = req.scope
    ? req.scope.split(" ").filter(Boolean)
    : client.scopes
  for (const s of requestedScopes) {
    if (!client.scopes.includes(s)) {
      return err(authError.invalidScope(`scope "${s}" not allowed for client`))
    }
  }

  // 3. Resolve m2m method instance.
  const m2mCfgs = tenantCfg.value.methods.filter(
    (m) => m.type === "m2m" && m.enabled,
  )
  if (m2mCfgs.length === 0) {
    return err(authError.methodNotFound("no enabled m2m method on tenant", {}))
  }
  if (m2mCfgs.length > 1) {
    return err(
      authError.methodNotFound(
        "multiple m2m methods configured — only one supported",
        {},
      ),
    )
  }
  const methodCfg = m2mCfgs[0]!
  const methodRes = await deps.methodCache.resolve(
    tenantCfg.value,
    methodCfg.id,
  )
  if (isErr(methodRes)) return err(methodRes.error)
  const method = methodRes.value
  if (!method.client) {
    return err(
      authError.methodNotFound(
        `m2m method "${methodCfg.id}" did not register a client fn`,
        { methodId: methodCfg.id, methodKind: method.kind },
      ),
    )
  }

  // 4. Dispatch the method's client fn.
  const clientResult = await method.client({
    clientID: req.clientId,
    clientSecret: req.clientSecret,
    params: req.params ?? {},
  })
  if (isErr(clientResult)) return err(clientResult.error)

  // 5. Build subject claim via user's success callback.
  const tenant: TenantContext = {
    id: tenantCfg.value.id,
    config: tenantCfg.value,
    request: { raw: new Request("about:blank"), custom: {} },
  }
  let claim: SubjectClaim
  try {
    claim = await deps.success({
      tenant,
      methodId: method.id,
      methodKind: method.kind,
      providerSubject: req.clientId,
      properties: clientResult.value,
      context: null,
    })
  } catch (e) {
    return err(authError.serverError("success callback threw", e))
  }

  const checked = await validateSubjectClaim(deps.subjects, claim)
  if (isErr(checked)) {
    await safeAudit(deps, {
      kind: "invalid_subject_claim",
      tenantId: tenant.id,
      clientId: client.id,
      subjectType: checked.error.rejection.subjectType,
      reason: checked.error.rejection.reason,
      detail: checked.error.rejection.detail,
      timestamp: deps.clock(),
    })
    return err(checked.error)
  }
  claim = checked.value

  // 6. Mint access only — RFC 6749 §4.4.3 says client_credentials SHOULD
  //    NOT issue a refresh token. `skipRefresh: true` keeps the token-
  //    store from accumulating orphaned rows that the response would
  //    otherwise strip.
  const minted = await mintTokens({
    tenant,
    claim,
    payload: {
      tenantId: tenant.id,
      clientId: client.id,
      methodId: method.id,
      methodKind: method.kind,
      scopes: requestedScopes,
      ...(client.scopes.includes("audience") ? {} : {}),
    },
    family: (deps.newRefreshFamily ?? randomId)(),
    skipRefresh: true,
    deps,
  })
  if (isErr(minted)) return err(minted.error)
  return ok(minted.value)
}
