/**
 * Test helper — build a ready-to-go IdP wired over memory adapters with a
 * single `redirectFactory` method. Conformance tests drive the HTTP surface
 * via `idp.handle(request)`.
 *
 * The harness centralizes the boilerplate (state keys, clock, tenant seed,
 * factory map, success callback) so individual cases stay short.
 */
import {
  MemoryAuditLog,
  MemoryConfigStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryTokenStore,
} from "../../src/adapters/memory"
import { createIdP } from "../../src/index"
import { s256Challenge } from "../../src/domain/pkce"
import type { IdP } from "../../src/types/idp"
import { asTenantId, type TenantConfig } from "../../src/types/tenant"
import { ok, type Result } from "../../src/types/result"
import type { AuthError } from "../../src/types/error"
import type { TenantId } from "../../src/types/tenant"

import { redirectFactory } from "./method"
import { buildStateKeys } from "./state-keys"
import { buildTenant } from "./tenant"

export type HarnessOptions = {
  /** Override the tenant seed. */
  tenant?: TenantConfig
  /** Override the issuer URL. */
  issuerUrl?: string
  /** Inject a deterministic clock. */
  clock?: () => number
}

export type Harness = {
  idp: IdP
  tenant: TenantConfig
  issuerUrl: string
  auditLog: MemoryAuditLog
  configStore: MemoryConfigStore
  sessionStore: MemorySessionStore
  tokenStore: MemoryTokenStore
  keyStore: MemoryKeyStore
  clock: () => number
  challengePair: { verifier: string; challenge: string }
}

export async function buildHarness(
  opts: HarnessOptions = {},
): Promise<Harness> {
  const tenant =
    opts.tenant ??
    (await buildTenant({
      methods: [{ id: "stub", kind: "stub" }],
    }))
  const issuerUrl = opts.issuerUrl ?? "https://idp.example"
  let now = 1_700_000_000_000
  const clock = opts.clock ?? (() => now)

  const auditLog = new MemoryAuditLog()
  const configStore = new MemoryConfigStore({ seed: [tenant] })
  const keyStore = new MemoryKeyStore({ clock })
  const tokenStore = new MemoryTokenStore({ keyStore, clock })
  const sessionStore = new MemorySessionStore({ clock })

  const idp = createIdP({
    resolveTenant: async (
      _req: Request,
    ): Promise<Result<TenantId, AuthError>> => ok(asTenantId(tenant.id)),
    stateKeys: buildStateKeys(),
    configStore,
    tokenStore,
    sessionStore,
    keyStore,
    auditLog,
    issuerUrl,
    methods: { stub: redirectFactory({ kind: "stub" }) as never },
    subjects: {} as never,
    success: async ({ providerSubject, properties }) =>
      ({
        type: "user",
        properties: { userId: providerSubject, ...(properties as object) },
      }) as never,
  })

  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  const challenge = await s256Challenge(verifier)

  // Note: we don't actually plumb the clock past memory adapters here because
  // createIdP uses Date.now() internally. Conformance tests do not rely on
  // time advancing — they exercise structural behavior.
  void clock
  void now

  return {
    idp,
    tenant,
    issuerUrl,
    auditLog,
    configStore,
    sessionStore,
    tokenStore,
    keyStore,
    clock,
    challengePair: { verifier, challenge },
  }
}

/** Convenience: build the standard `/authorize` query string. */
export function authorizeUrl(
  base: string,
  params: Record<string, string>,
): string {
  const u = new URL(base + "/authorize")
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v)
  return u.toString()
}

/** Convenience: form-encoded request to `/token`. */
export function tokenRequest(
  base: string,
  body: Record<string, string>,
): Request {
  return new Request(base + "/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  })
}

/** Walk the upstream redirect → fake callback so the IdP issues an auth code. */
export async function driveCallback(
  idp: IdP,
  upstreamRedirect: string,
): Promise<Response> {
  const upstream = new URL(upstreamRedirect)
  const state = upstream.searchParams.get("state")!
  const cb = upstream.searchParams.get("redirect_uri")!
  const cbUrl = new URL(cb)
  cbUrl.searchParams.set("state", state)
  cbUrl.searchParams.set("code", "upstream-code")
  return idp.handle(new Request(cbUrl.toString()))
}
