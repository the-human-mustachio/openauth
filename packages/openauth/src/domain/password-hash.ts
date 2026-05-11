/**
 * Pluggable password hasher.
 *
 * Default: **argon2id** (RFC 9106, OWASP 2024 recommendation) via
 * `@noble/hashes/argon2`. Pure JS, edge-compatible, no native deps.
 *
 * Tuning defaults follow the RFC 9106 §4 second recommended setting
 * (`t=3, m=64 MiB, p=4`). Operators with tight memory budgets (edge
 * platforms with strict per-request memory caps) can swap in their own
 * hasher via `passwordMethod({ hasher: customHasher })`.
 *
 * The serialized hash format is the canonical PHC string
 * (`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`) so users can verify
 * existing hashes from any conforming implementation.
 */
import { argon2idAsync } from "@noble/hashes/argon2.js"

import {
  base64url,
  randomBytes,
  timingSafeEqualStr,
  utf8,
} from "./crypto"

export type PasswordHasher = {
  /** Hash the password; output includes salt + parameters. */
  hash(plain: string): Promise<string>
  /** Verify a plain password against a previously stored hash. */
  verify(plain: string, stored: string): Promise<boolean>
}

export type Argon2idParams = {
  /** Time cost. RFC 9106 §4 recommends `t=3` for the 64 MiB profile. */
  t: number
  /** Memory cost in KiB. RFC 9106 §4 recommends `65536` (64 MiB). */
  m: number
  /** Parallelism. RFC 9106 §4 recommends `4`. */
  p: number
  /** Output length in bytes. 32 is standard. */
  dkLen: number
  /** Salt length in bytes. 16 is the RFC 9106 minimum. */
  saltLen: number
}

export const DEFAULT_ARGON2ID_PARAMS: Argon2idParams = {
  t: 3,
  m: 65536,
  p: 4,
  dkLen: 32,
  saltLen: 16,
}

/**
 * Build an argon2id `PasswordHasher`. Stored hashes use the canonical PHC
 * string format so they're interoperable with any RFC 9106 implementation.
 */
export function argon2idHasher(
  params: Partial<Argon2idParams> = {},
): PasswordHasher {
  const cfg = { ...DEFAULT_ARGON2ID_PARAMS, ...params }
  return {
    async hash(plain: string): Promise<string> {
      const salt = randomBytes(cfg.saltLen)
      const out = await argon2idAsync(utf8.encode(plain), salt, {
        t: cfg.t,
        m: cfg.m,
        p: cfg.p,
        dkLen: cfg.dkLen,
      })
      return `$argon2id$v=19$m=${cfg.m},t=${cfg.t},p=${cfg.p}$${base64url.encode(salt)}$${base64url.encode(out as Uint8Array)}`
    },
    async verify(plain: string, stored: string): Promise<boolean> {
      const parsed = parsePhc(stored)
      if (!parsed) return false
      if (parsed.algo !== "argon2id") return false
      try {
        const out = await argon2idAsync(utf8.encode(plain), parsed.salt, {
          t: parsed.t,
          m: parsed.m,
          p: parsed.p,
          dkLen: parsed.hash.length,
        })
        return timingSafeEqualStr(
          base64url.encode(out as Uint8Array),
          base64url.encode(parsed.hash),
        )
      } catch {
        return false
      }
    },
  }
}

type Phc = {
  algo: string
  t: number
  m: number
  p: number
  salt: Uint8Array
  hash: Uint8Array
}

function parsePhc(stored: string): Phc | null {
  // Format: $algo$v=19$m=N,t=N,p=N$<saltb64u>$<hashb64u>
  const parts = stored.split("$")
  if (parts.length !== 6) return null
  const [, algo, _version, params, saltStr, hashStr] = parts
  if (!algo || !params || !saltStr || !hashStr) return null
  const kv = Object.fromEntries(
    params.split(",").map((p) => {
      const [k, v] = p.split("=")
      return [k ?? "", Number.parseInt(v ?? "0", 10)]
    }),
  )
  if (
    typeof kv.m !== "number" ||
    typeof kv.t !== "number" ||
    typeof kv.p !== "number"
  ) {
    return null
  }
  try {
    return {
      algo,
      t: kv.t,
      m: kv.m,
      p: kv.p,
      salt: base64url.decode(saltStr),
      hash: base64url.decode(hashStr),
    }
  } catch {
    return null
  }
}
