/**
 * Low-level crypto + encoding helpers used across the domain.
 *
 * Web Crypto only. No `node:*` imports — domain code runs on every runtime
 * we target (Node 18+, Bun, Workers, Lambda).
 */
import { base64url as joseB64u, CompactEncrypt, compactDecrypt } from "jose"

/** 256-bit random token, base64url-encoded. ~43 chars. */
export function randomToken(): string {
  const buf = new Uint8Array(32)
  crypto.getRandomValues(buf)
  return joseB64u.encode(buf)
}

/** 128-bit random id, base64url-encoded. ~22 chars. */
export function randomId(): string {
  const buf = new Uint8Array(16)
  crypto.getRandomValues(buf)
  return joseB64u.encode(buf)
}

/** Cryptographic random hex string of `bytes` length. */
export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("")
}

/** Cryptographic random `Uint8Array` of `bytes` length. */
export function randomBytes(bytes: number): Uint8Array {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return buf
}

/** Base64url encode raw bytes (jose alias for downstream consistency). */
export const base64url = {
  encode: (data: Uint8Array | string): string => joseB64u.encode(data),
  decode: (s: string): Uint8Array => joseB64u.decode(s),
}

/** UTF-8 helpers. */
export const utf8 = {
  encode: (s: string): Uint8Array => new TextEncoder().encode(s),
  decode: (b: Uint8Array): string => new TextDecoder().decode(b),
}

/**
 * Constant-time byte-array compare. Returns false fast on length mismatch
 * (length itself is not secret), then XORs every byte to avoid early exit.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

/** Constant-time string compare (UTF-8 bytes). */
export function timingSafeEqualStr(a: string, b: string): boolean {
  return timingSafeEqual(utf8.encode(a), utf8.encode(b))
}

/** SHA-256 digest. */
export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? utf8.encode(data) : data
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return new Uint8Array(digest)
}

/** Import a 32-byte HMAC-SHA-256 key for sign/verify use. */
export async function importHmacKey(
  raw: Uint8Array,
  usage: ReadonlyArray<"sign" | "verify"> = ["sign", "verify"],
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: "SHA-256" },
    false,
    [...usage],
  )
}

/** HMAC-SHA-256 sign. */
export async function hmacSign(
  key: CryptoKey,
  message: Uint8Array,
): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign("HMAC", key, message)
  return new Uint8Array(sig)
}

/**
 * HMAC-SHA-256 verify. `crypto.subtle.verify` is timing-safe by spec, which
 * is why we use it instead of recomputing + comparing manually.
 */
export async function hmacVerify(
  key: CryptoKey,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  return crypto.subtle.verify("HMAC", key, signature, message)
}

/**
 * Encrypt a JSON-serializable payload with AES-256-GCM under the supplied
 * 256-bit key. Output is a compact JWE string (`{header}.{enc-key}.{iv}.{ct}.{tag}`).
 *
 * Used for `TokenStore.saveCode` — the auth-code payload is encrypted at
 * rest. The compact-JWE format embeds the `kid` so `consumeCode` can pick
 * the right key during overlap rotation.
 *
 * For symmetric direct encryption we use `dir` with `A256GCM`, so the
 * supplied `keyBytes` is the content-encryption key itself.
 */
export async function encryptPayload(
  payload: unknown,
  kid: string,
  keyBytes: Uint8Array,
): Promise<string> {
  if (keyBytes.byteLength !== 32) {
    throw new Error(
      `encryptPayload: keyBytes must be 32 bytes (A256GCM); got ${keyBytes.byteLength}`,
    )
  }
  const cek = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  )
  const json = utf8.encode(JSON.stringify(payload))
  return new CompactEncrypt(json)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", kid })
    .encrypt(cek)
}

/** Inverse of {@link encryptPayload}. Returns the parsed JSON payload. */
export async function decryptPayload<T = unknown>(
  jwe: string,
  resolveKey: (kid: string) => Promise<Uint8Array>,
): Promise<T> {
  const { plaintext } = await compactDecrypt(jwe, async (header) => {
    const kid = header.kid
    if (typeof kid !== "string") {
      throw new Error("decryptPayload: missing kid in JWE header")
    }
    const raw = await resolveKey(kid)
    return crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    )
  })
  return JSON.parse(utf8.decode(plaintext)) as T
}

/** Generate a fresh 32-byte AES-256 / HMAC-SHA-256 key. */
export function generateSymmetricKey(): Uint8Array {
  const buf = new Uint8Array(32)
  crypto.getRandomValues(buf)
  return buf
}
