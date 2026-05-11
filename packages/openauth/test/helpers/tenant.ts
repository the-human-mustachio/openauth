/**
 * Test helper — build seeded `TenantConfig` records.
 */
import {
  asTenantId,
  type TenantConfig,
  type TenantId,
} from "../../src/types/tenant"

import { hashClientSecret } from "../../src/domain/token"

export type BuildTenantOpts = {
  id?: string
  clientId?: string
  clientType?: "public" | "confidential"
  clientSecretPlain?: string
  redirectUri?: string
  scopes?: string[]
  pkceRequired?: boolean
  methods?: Array<{
    id: string
    kind: string
    enabled?: boolean
    config?: Record<string, unknown>
  }>
}

export async function buildTenant(
  opts: BuildTenantOpts = {},
): Promise<TenantConfig> {
  const id = asTenantId(opts.id ?? "acme")
  const client = {
    id: opts.clientId ?? "rp-1",
    name: "Test RP",
    type: opts.clientType ?? ("public" as "public" | "confidential"),
    redirectUris: [opts.redirectUri ?? "https://app.example/callback"],
    grantTypes: ["authorization_code", "refresh_token"] as Array<
      "authorization_code" | "refresh_token" | "client_credentials"
    >,
    scopes: opts.scopes ?? ["openid", "email", "profile"],
    pkceRequired: opts.pkceRequired ?? true,
  }
  if (opts.clientType === "confidential" && opts.clientSecretPlain) {
    Object.assign(client, {
      secretHash: await hashClientSecret(opts.clientSecretPlain),
    })
  }

  const methods = opts.methods?.map((m) => ({
    id: m.id,
    kind: m.kind,
    type: "custom" as const,
    enabled: m.enabled ?? true,
    config: m.config ?? {},
  })) ?? [
    {
      id: "stub",
      kind: "stub",
      type: "custom" as const,
      enabled: true,
      config: {},
    },
  ]

  return {
    id,
    displayName: "Acme",
    clients: [client],
    methods,
  } satisfies TenantConfig
}

export function tenantContextFor(config: TenantConfig, req?: Request) {
  return {
    id: config.id as TenantId,
    config,
    request: {
      raw: req ?? new Request("https://idp.example/authorize"),
      custom: {},
    },
  }
}
