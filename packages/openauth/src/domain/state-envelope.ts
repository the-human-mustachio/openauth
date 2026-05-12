/**
 * MAC-signed `state` envelope used by the tenant-recovery chain.
 *
 * Format (intentionally compact, well under 256 base64url bytes):
 *
 *   `<b64u(payloadJson)>.<b64u(hmacSha256(payloadJson, key[kid]))>`
 *
 * where `payloadJson` is canonical JSON over `{tenantId, flowId, nonce, kid}`.
 *
 * **Nothing sensitive is in the envelope** — only the minimal recovery
 * tuple. Sensitive data (`clientPkce`, `appRedirectUri`, scopes, etc.)
 * lives in the server-side `FlowRecord`, identified by `flowId`.
 *
 * See `ARCHITECTURE.md` §"Tenant recovery across redirects" and plan
 * §"Crypto — HMAC-SHA-256".
 */
import { authError, type AuthError } from "../types/error"
import type { Result } from "../types/result"
import { err, ok } from "../types/result"
import type {
  StateEnvelope,
  StateKey,
  StateKeyRing,
  TenantId,
} from "../types/tenant"
import { asTenantId } from "../types/tenant"

import { base64url, hmacSign, hmacVerify, importHmacKey, utf8 } from "./crypto"

/**
 * Serialize envelope fields in a fixed order so the MAC input is
 * deterministic regardless of object-key insertion order.
 */
function canonicalize(env: StateEnvelope): string {
  return JSON.stringify({
    tenantId: env.tenantId,
    flowId: env.flowId,
    nonce: env.nonce,
    kid: env.kid,
  })
}

/** Mint a signed state string for the given envelope under the active key. */
export async function mintStateEnvelope(
  envelope: Omit<StateEnvelope, "kid">,
  keyRing: StateKeyRing,
): Promise<string> {
  const active = keyRing.active
  const stamped: StateEnvelope = { ...envelope, kid: active.kid }
  const payloadBytes = utf8.encode(canonicalize(stamped))
  const key = await importHmacKey(active.key, ["sign"])
  const sig = await hmacSign(key, payloadBytes)
  return `${base64url.encode(payloadBytes)}.${base64url.encode(sig)}`
}

/**
 * Verify and parse a state string. Returns `unknown_state` on malformed
 * input, unknown `kid`, or signature mismatch.
 *
 * The MAC verification step uses `crypto.subtle.verify`, which is
 * timing-safe by spec.
 */
export async function verifyStateEnvelope(
  state: string,
  keyRing: StateKeyRing,
): Promise<Result<StateEnvelope, AuthError>> {
  if (typeof state !== "string" || !state.includes(".")) {
    return err(authError.unknownState("malformed state"))
  }
  const dotIdx = state.indexOf(".")
  const headerB64u = state.slice(0, dotIdx)
  const sigB64u = state.slice(dotIdx + 1)
  if (!headerB64u || !sigB64u || sigB64u.includes(".")) {
    return err(authError.unknownState("malformed state"))
  }

  let payloadBytes: Uint8Array
  let sigBytes: Uint8Array
  try {
    payloadBytes = base64url.decode(headerB64u)
    sigBytes = base64url.decode(sigB64u)
  } catch {
    return err(authError.unknownState("malformed state encoding"))
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(utf8.decode(payloadBytes))
  } catch {
    return err(authError.unknownState("malformed state payload"))
  }
  if (!isEnvelopeShape(parsed)) {
    return err(authError.unknownState("state payload missing fields"))
  }

  const candidate = findKey(keyRing, parsed.kid)
  if (!candidate) {
    return err(authError.unknownState(`unknown state kid "${parsed.kid}"`))
  }

  const key = await importHmacKey(candidate.key, ["verify"])
  const okSig = await hmacVerify(key, sigBytes, payloadBytes)
  if (!okSig) {
    return err(authError.unknownState("state signature mismatch"))
  }

  // Cross-check that the payload's `kid` matches the verifying key — guards
  // against a malicious sender re-encoding the header to claim a different
  // key was used while the MAC was actually computed under another.
  if (parsed.kid !== candidate.kid) {
    return err(authError.unknownState("state kid drift"))
  }

  return ok({
    tenantId: asTenantId(parsed.tenantId),
    flowId: parsed.flowId,
    nonce: parsed.nonce,
    kid: parsed.kid,
  })
}

function findKey(ring: StateKeyRing, kid: string): StateKey | undefined {
  return ring.verify.find((k) => k.kid === kid)
}

type EnvelopeShape = {
  tenantId: TenantId & string
  flowId: string
  nonce: string
  kid: string
}

function isEnvelopeShape(value: unknown): value is EnvelopeShape {
  if (!value || typeof value !== "object") return false
  const v = value as Record<string, unknown>
  return (
    typeof v.tenantId === "string" &&
    typeof v.flowId === "string" &&
    typeof v.nonce === "string" &&
    typeof v.kid === "string"
  )
}
