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

import { safeAudit } from "./audit"
import { verifyClientCredentials } from "./client-auth"
import {
  base64url,
  decryptPayload,
  encryptPayload,
  randomId,
  randomToken,
  sha256,
  utf8,
} from "./crypto"
import { buildIdTokenClaims, shouldIssueIdToken } from "./id-token"
import { signAccessToken, signIdToken } from "./jwt"
import { validatePkce } from "./pkce"

/**
 * Encrypt a `CodePayload` with the active `KeyStore` encryption key and
 * persist it via `tokenStore.saveCode`. Centralizes the encrypt-then-store
 * pattern so adapters never see plaintext (M1).
 */
export async function saveEncryptedCode(
  code: string,
  payload: CodePayload,
  ttl: number,
  deps: { keyStore: KeyStore; tokenStore: TokenStore },
): Promise<Result<void, AuthError>> {
  const keyResult = await deps.keyStore.currentEncryptionKey()
  if (isErr(keyResult)) return err(keyResult.error)
  let ciphertext: string
  try {
    ciphertext = await encryptPayload(
      payload,
      keyResult.value.kid,
      keyResult.value.keyRef as Uint8Array,
    )
  } catch (e) {
    return err(authError.internalError("saveEncryptedCode: encrypt failed", e))
  }
  return deps.tokenStore.saveCode(code, ciphertext, ttl)
}

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
  /**
   * RFC 9449 §6 — the JWK thumbprint of the presented DPoP proof. Set by
   * the HTTP layer after verifying the `DPoP:` header against this
   * request's actual method + URI. The domain binds the issued access
   * token to this thumbprint via `cnf.jkt`.
   */
  dpopJkt?: string
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
  /**
   * Host-supplied vendor scope → claim-names map. Forwarded to `mintTokens`
   * for id_token + /userinfo scope-gating. See `IdPOptions.customScopeClaims`.
   */
  customScopeClaims?: Record<string, ReadonlyArray<string>>
}

export async function exchangeCode(
  req: TokenAuthCodeRequest,
  deps: ExchangeCodeDeps,
): Promise<Result<TokenResponse, AuthError>> {
  // 1. Consume code (atomic; failure here means unknown / consumed / expired).
  //    The adapter returns the ciphertext blob verbatim — encryption is
  //    the domain's job (M1), so decrypt here before reading any field.
  const consumed = await deps.tokenStore.consumeCode(req.code)
  if (isErr(consumed)) return err(consumed.error)
  let payload: CodePayload
  try {
    payload = await decryptPayload<CodePayload>(consumed.value, async (kid) => {
      const keyResult = await deps.keyStore.getEncryptionKey(kid)
      if (isErr(keyResult)) {
        throw new Error(`unknown encryption kid ${kid}`)
      }
      return keyResult.value.keyRef as Uint8Array
    })
  } catch (e) {
    return err(authError.internalError("exchangeCode: decrypt failed", e))
  }

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

  // RFC 9449 §5.2 — if the client is configured to require DPoP, a
  // bearer-only request (no DPoP header → no `dpopJkt` threaded in) is
  // refused with `invalid_dpop_proof` before any token is minted.
  if (client.dpopRequired && req.dpopJkt === undefined) {
    return err(
      authError.invalidDpopProof(
        `client "${client.id}" requires DPoP-bound tokens`,
      ),
    )
  }

  // 4. Redirect URI binding.
  if (payload.appRedirectUri !== req.redirectUri) {
    return err(authError.invalidGrant("redirect_uri mismatch with auth code"))
  }

  // 5. PKCE check (RP → IdP).
  if (payload.clientPkce) {
    if (!req.codeVerifier) {
      return err(authError.invalidGrant("missing code_verifier"))
    }
    const pkceValid = await validatePkce(
      req.codeVerifier,
      payload.clientPkce.challenge,
    )
    if (!pkceValid) {
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

  // 8. Mint access + refresh (+ id_token if `openid` scope was granted).
  const minted = await mintTokens({
    tenant,
    claim,
    payload: {
      ...payload,
      ...(req.dpopJkt !== undefined ? { dpopJkt: req.dpopJkt } : {}),
    },
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
  > & {
    /**
     * Present on `authorization_code` and `refresh_token` grants where an
     * end-user actually authenticated. Absent on `client_credentials`
     * (no end-user) — and absent means no `id_token` is emitted even if
     * the requested scopes nominally include `openid`.
     */
    authTime?: number
    /** RP's OIDC `nonce` from `/authorize`, when present. */
    appNonce?: string
    /**
     * DPoP key thumbprint (RFC 9449 §6.1). When present, the access
     * token's `cnf.jkt` claim is set and `token_type` flips to `"DPoP"`;
     * the saved refresh-token payload's `dpopJkt` is set so refresh
     * rotation re-enforces sender constraint.
     */
    dpopJkt?: string
    /**
     * OIDC Core §5.5 — RP-requested claims from `/authorize`. Carried
     * into the id_token and forward across refresh rotations (§12) so
     * later /userinfo calls keep returning the requested fields.
     */
    claimsRequest?: import("../types/authorization").ClaimsRequest
  }
  family: string
  /**
   * `client_credentials` grants (RFC 6749 §4.4.3) and other paths where a
   * refresh token is not appropriate set `skipRefresh: true`. The response
   * then omits `refresh_token` and **no row is written** to `TokenStore`,
   * so the durable store doesn't accumulate orphaned refresh entries that
   * the response strips and discards.
   */
  skipRefresh?: boolean
  deps: {
    keyStore: KeyStore
    tokenStore: TokenStore
    auditLog?: AuditLog
    issuerUrl: string
    clock: () => number
    newRefreshToken?: () => string
    /**
     * Host-supplied vendor scope → claim-names map merged into the
     * id_token + /userinfo scope-gating. See `IdPOptions.customScopeClaims`.
     */
    customScopeClaims?: Record<string, ReadonlyArray<string>>
  }
}): Promise<Result<TokenResponse, AuthError>> {
  const { tenant, claim, payload, deps, family, skipRefresh } = args
  const accessTtl =
    tenant.config.accessTtl !== undefined
      ? tenant.config.accessTtl * 1000
      : DEFAULT_ACCESS_TTL_MS
  const refreshTtl =
    tenant.config.refreshTtl !== undefined
      ? tenant.config.refreshTtl * 1000
      : DEFAULT_REFRESH_TTL_MS
  const now = deps.clock()
  // OIDC Core §8.1 — `sectorIdentifier` from the receiving client drives
  // pairwise vs public subject derivation. Look it up off the tenant
  // config (already loaded by the grant flow). Absent = public.
  const receivingClient = tenant.config.clients.find(
    (c) => c.id === payload.clientId,
  )
  const subjectId = await deriveSubjectId(
    claim,
    receivingClient?.sectorIdentifier,
  )

  const keyRes = await deps.keyStore.currentSigningKey()
  if (isErr(keyRes)) return err(keyRes.error)
  const signingKey = keyRes.value

  const userinfoClaimNames = Object.keys(
    payload.claimsRequest?.userinfo ?? {},
  )
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
    ...(payload.authTime !== undefined ? { auth_time: payload.authTime } : {}),
    ...(payload.dpopJkt !== undefined
      ? { cnf: { jkt: payload.dpopJkt } }
      : {}),
    ...(userinfoClaimNames.length > 0 ? { uic: userinfoClaimNames } : {}),
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

  let refresh: string | undefined
  if (!skipRefresh) {
    refresh = (deps.newRefreshToken ?? randomToken)()
    const refreshPayload: RefreshTokenPayload = {
      tenantId: payload.tenantId,
      clientId: payload.clientId,
      subjectId,
      claim,
      scopes: payload.scopes,
      audience: payload.audience,
      family,
      methodId: payload.methodId,
      methodKind: payload.methodKind,
      // Carry the original end-user auth time forward. Refresh-grant
      // reissue uses this verbatim so `id_token.auth_time` is stable per
      // OIDC Core §12 (refresh does not re-authenticate the user).
      authTime: payload.authTime ?? Math.floor(now / 1000),
      ...(payload.dpopJkt !== undefined ? { dpopJkt: payload.dpopJkt } : {}),
      ...(payload.claimsRequest !== undefined
        ? { claimsRequest: payload.claimsRequest }
        : {}),
      issuedAt: now,
      expiresAt: now + refreshTtl,
    }
    const saved = await deps.tokenStore.saveRefresh(refresh, refreshPayload)
    if (isErr(saved)) return err(saved.error)
  }

  // OIDC id_token issuance — only when the grant carried an end-user
  // (`authTime` present) AND `openid` scope was granted. Client-credentials
  // never satisfies the first condition; refresh + code do.
  let idToken: string | undefined
  if (payload.authTime !== undefined && shouldIssueIdToken(payload.scopes)) {
    const idClaims = await buildIdTokenClaims({
      issuerUrl: deps.issuerUrl,
      audience: payload.clientId,
      subjectId,
      claim,
      scopes: payload.scopes,
      authTime: payload.authTime,
      ...(payload.appNonce !== undefined ? { appNonce: payload.appNonce } : {}),
      now,
      methodKind: payload.methodKind,
      accessToken,
      ...(payload.claimsRequest !== undefined
        ? { claimsRequest: payload.claimsRequest }
        : {}),
      ...(deps.customScopeClaims !== undefined
        ? { customScopeClaims: deps.customScopeClaims }
        : {}),
    })
    try {
      idToken = await signIdToken(
        idClaims,
        signingKey.privateKeyRef as Parameters<typeof signIdToken>[1],
        signingKey.alg,
        signingKey.kid,
      )
    } catch (e) {
      return err(authError.serverError("id_token sign failed", e))
    }
  }

  await safeAudit(deps, {
    kind: "token_issued",
    tenantId: payload.tenantId,
    clientId: payload.clientId,
    methodId: payload.methodId,
    methodKind: payload.methodKind,
    subjectId,
    refreshTokenIdHash: refresh ? await hashTokenForAudit(refresh) : "",
    ...(idToken !== undefined ? { idTokenIssued: true } : {}),
    ...(payload.dpopJkt !== undefined ? { dpopBound: true } : {}),
    timestamp: now,
  })

  return ok({
    access_token: accessToken,
    token_type: payload.dpopJkt !== undefined ? "DPoP" : "Bearer",
    expires_in: Math.floor(accessTtl / 1000),
    ...(refresh !== undefined ? { refresh_token: refresh } : {}),
    ...(idToken !== undefined ? { id_token: idToken } : {}),
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
 *
 * OIDC Core §8.1 — when `sectorIdentifier` is supplied, the derivation
 * mixes it in so the resulting `sub` is **pairwise**: identical across
 * clients sharing that sector, distinct across sectors. Absent =
 * **public** subject (same `sub` for every RP).
 */
async function deriveSubjectId(
  claim: SubjectClaim,
  sectorIdentifier?: string,
): Promise<string> {
  const c = claim as { type: string; properties: Record<string, unknown> }
  const ordered = canonicalize(c.properties)
  const seed =
    sectorIdentifier !== undefined
      ? `${sectorIdentifier}\0${c.type}\0${ordered}`
      : `${c.type}\0${ordered}`
  return base64url.encode(await sha256(seed)).slice(0, 22)
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
