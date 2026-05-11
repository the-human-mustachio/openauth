/**
 * `/token` endpoint logic for `grant_type=authorization_code`.
 *
 * Steps:
 *   1. Authenticate client (public: id only; confidential: id + secret).
 *   2. `TokenStore.consumeCode(code)` — strong CAS; returns the decrypted
 *      `CodePayload`.
 *   3. Verify the consumed code matches the request (`client_id`,
 *      `redirect_uri`). Any mismatch → `invalid_grant`.
 *   4. Verify PKCE if the code carries a `clientPkce` (RP→IdP PKCE).
 *   5. Call the user's `success` callback with `SuccessMapInput` to mint
 *      the `SubjectClaim` — the same role the legacy `auth.success`
 *      callback plays in `issuer.ts`.
 *   6. (Optional) `persistUpstreamTokens` hook — runs here, not at
 *      callback time, so failed exchanges don't pollute the secrets store.
 *   7. Mint access (JWT, ES256) + refresh (random opaque) tokens, save
 *      refresh, audit `token_issued`.
 *
 * Refresh-grant logic lives in `./refresh.ts`. Revocation in `./revoke.ts`.
 */
import type { AuditLog } from "../ports/audit-log"
import type { KeyStore } from "../ports/key-store"
import type { TokenStore } from "../ports/token-store"
import type { ConfigStore } from "../ports/config-store"
import type { AuthError } from "../types/error"
import { authError } from "../types/error"
import type { PersistUpstreamTokens, SuccessMapInput } from "../types/idp"
import type { Result } from "../types/result"
import { err, isErr, ok } from "../types/result"
import type { SubjectClaim } from "../types/subject"
import type { TenantContext } from "../types/tenant"
import type {
  AccessTokenClaims,
  CodePayload,
  RefreshTokenPayload,
  TokenResponse,
} from "../types/token"

import { verifyClientCredentials } from "./client-auth"
import {
  base64url,
  randomId,
  randomToken,
  sha256,
  utf8,
} from "./crypto"
import { signAccessToken } from "./jwt"
import { validatePkce } from "./pkce"

export const DEFAULT_ACCESS_TTL_MS = 15 * 60 * 1000
export const DEFAULT_REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000

export type TokenAuthCodeRequest = {
  grantType: "authorization_code"
  code: string
  redirectUri: string
  clientId: string
  /** Confidential clients only. */
  clientSecret?: string
  /** Required if the original `/authorize` request had a `code_challenge`. */
  codeVerifier?: string
}

export type ExchangeCodeDeps = {
  configStore: ConfigStore
  tokenStore: TokenStore
  keyStore: KeyStore
  auditLog?: AuditLog
  success: (input: SuccessMapInput) => Promise<SubjectClaim>
  persistUpstreamTokens?: PersistUpstreamTokens
  issuerUrl: string
  clock: () => number
  newRefreshToken?: () => string
  /** Test override. */
  newRefreshFamily?: () => string
}

export async function exchangeCode(
  req: TokenAuthCodeRequest,
  deps: ExchangeCodeDeps,
): Promise<Result<TokenResponse, AuthError>> {
  // 1. Consume code (atomic; failure here means unknown / consumed / expired).
  const consumed = await deps.tokenStore.consumeCode(req.code)
  if (isErr(consumed)) return err(consumed.error)
  const payload = consumed.value

  // 2. Load tenant + client.
  const tenantCfg = await deps.configStore.getTenantConfig(payload.tenantId)
  if (isErr(tenantCfg)) return err(tenantCfg.error)
  const client = tenantCfg.value.clients.find((c) => c.id === payload.clientId)
  if (!client) {
    return err(authError.invalidClient(`unknown client "${payload.clientId}"`))
  }

  // 3. Client auth.
  if (client.id !== req.clientId) {
    return err(authError.invalidGrant("client_id mismatch with auth code"))
  }
  const authResult = await verifyClientCredentials(client, req.clientSecret)
  if (authResult) return err(authResult)

  // 4. Redirect URI binding.
  if (payload.appRedirectUri !== req.redirectUri) {
    return err(authError.invalidGrant("redirect_uri mismatch with auth code"))
  }

  // 5. PKCE check (RP → IdP).
  if (payload.clientPkce) {
    if (!req.codeVerifier) {
      return err(authError.invalidGrant("missing code_verifier"))
    }
    const ok = await validatePkce(
      req.codeVerifier,
      payload.clientPkce.challenge,
    )
    if (!ok) {
      return err(authError.invalidGrant("PKCE verification failed"))
    }
  }

  // 6. Build the subject claim via user's success callback.
  const tenant: TenantContext = {
    id: payload.tenantId,
    config: tenantCfg.value,
    request: { raw: new Request("about:blank"), custom: {} },
  }
  let claim: SubjectClaim
  try {
    claim = await deps.success({
      tenant,
      methodId: payload.methodId,
      methodKind: payload.methodKind,
      providerSubject: payload.providerSubject,
      properties: payload.properties,
      context: payload.context ?? null,
    })
  } catch (e) {
    return err(authError.serverError("success callback threw", e))
  }

  // 7. Optional upstream-tokens hook (runs after success, before
  //    mint — failed mints below should NOT roll back this hook because
  //    by contract the hook itself decides whether to persist).
  if (deps.persistUpstreamTokens) {
    try {
      await deps.persistUpstreamTokens({
        tenant,
        methodId: payload.methodId,
        methodKind: payload.methodKind,
        providerSubject: payload.providerSubject,
        properties: payload.properties,
        subjectClaim: claim,
      })
    } catch (e) {
      return err(authError.serverError("persistUpstreamTokens hook threw", e))
    }
  }

  // 8. Mint access + refresh.
  const minted = await mintTokens({
    tenant,
    claim,
    payload,
    deps,
    family: (deps.newRefreshFamily ?? randomId)(),
  })
  return minted
}

/**
 * Shared mint logic used by both `exchangeCode` and `refreshTokens` (which
 * passes its previous `family` through to preserve the rotation chain).
 */
export async function mintTokens(args: {
  tenant: TenantContext
  claim: SubjectClaim
  payload: Pick<
    CodePayload,
    "tenantId" | "clientId" | "methodId" | "methodKind" | "scopes" | "audience"
  >
  family: string
  deps: {
    keyStore: KeyStore
    tokenStore: TokenStore
    auditLog?: AuditLog
    issuerUrl: string
    clock: () => number
    newRefreshToken?: () => string
  }
}): Promise<Result<TokenResponse, AuthError>> {
  const { tenant, claim, payload, deps, family } = args
  const accessTtl = (tenant.config.accessTtl ?? 15 * 60) * 1000
  const refreshTtl = (tenant.config.refreshTtl ?? 30 * 24 * 60 * 60) * 1000
  const now = deps.clock()
  const subjectId = await deriveSubjectId(claim)

  const keyRes = await deps.keyStore.currentSigningKey()
  if (isErr(keyRes)) return err(keyRes.error)
  const signingKey = keyRes.value

  const claims: AccessTokenClaims = {
    iss: deps.issuerUrl,
    sub: subjectId,
    aud: payload.audience ?? payload.clientId,
    exp: Math.floor((now + accessTtl) / 1000),
    iat: Math.floor(now / 1000),
    tid: payload.tenantId,
    mid: payload.methodId,
    mkind: payload.methodKind,
    scope: payload.scopes.join(" "),
    claim,
  }

  let accessToken: string
  try {
    accessToken = await signAccessToken(
      claims,
      // jose's KeyLike covers both CryptoKey (Web Crypto) and the
      // node:crypto KeyObject — the in-memory KeyStore stashes the result
      // of generateKeyPair directly.
      signingKey.privateKeyRef as Parameters<typeof signAccessToken>[1],
      signingKey.alg,
      signingKey.kid,
    )
  } catch (e) {
    return err(authError.serverError("access token sign failed", e))
  }

  const refresh = (deps.newRefreshToken ?? randomToken)()
  const refreshPayload: RefreshTokenPayload = {
    tenantId: payload.tenantId,
    clientId: payload.clientId,
    subjectId,
    claim,
    scopes: payload.scopes,
    audience: payload.audience,
    family,
    issuedAt: now,
    expiresAt: now + refreshTtl,
  }
  const saved = await deps.tokenStore.saveRefresh(refresh, refreshPayload)
  if (isErr(saved)) return err(saved.error)

  await audit(deps, {
    kind: "token_issued",
    tenantId: payload.tenantId,
    clientId: payload.clientId,
    methodId: payload.methodId,
    methodKind: payload.methodKind,
    subjectId,
    refreshTokenIdHash: await hashTokenForAudit(refresh),
    timestamp: now,
  })

  return ok({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(accessTtl / 1000),
    refresh_token: refresh,
    scope: payload.scopes.join(" "),
  })
}

/**
 * Phase 2 client-secret hash format: SHA-256 over UTF-8 bytes, base64url.
 *
 * Production deployments will move to argon2id (per cross-cutting
 * decisions) in Phase 8. The storage shape (`ClientConfig.secretHash:
 * string`) is unchanged; only the hashing function swaps.
 */
export async function hashClientSecret(plain: string): Promise<string> {
  return base64url.encode(await sha256(utf8.encode(plain)))
}

/**
 * Derive a stable subject id from the issued `SubjectClaim`. Hash inputs
 * are canonicalized so reordered `properties` keys hash identically.
 */
async function deriveSubjectId(claim: SubjectClaim): Promise<string> {
  const c = claim as { type: string; properties: Record<string, unknown> }
  const ordered = canonicalize(c.properties)
  return base64url.encode(await sha256(`${c.type}\0${ordered}`)).slice(0, 22)
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return JSON.stringify(value)
  }
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`
}

async function hashTokenForAudit(token: string): Promise<string> {
  return base64url.encode(await sha256(utf8.encode(token))).slice(0, 16)
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
