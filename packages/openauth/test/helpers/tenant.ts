/**
 * Test helper — build seeded `TenantConfig` records.
 */
import {
  asTenantId,
  type ClientConfig,
  type GrantType,
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
  const grantTypes: GrantType[] = ["authorization_code", "refresh_token"]
  const scopes = opts.scopes ?? ["openid", "email", "profile"]
  const redirectUris = [opts.redirectUri ?? "https://app.example/callback"]
  const clientId = opts.clientId ?? "rp-1"
  const clientType = opts.clientType ?? "public"
  let client: ClientConfig
  if (clientType === "confidential") {
    client = {
      id: clientId,
      name: "Test RP",
      type: "confidential",
      secretHash: opts.clientSecretPlain
        ? await hashClientSecret(opts.clientSecretPlain)
        : "",
      redirectUris,
      grantTypes,
      scopes,
      pkceRequired: opts.pkceRequired ?? true,
    }
  } else {
    client = {
      id: clientId,
      name: "Test RP",
      type: "public",
      redirectUris,
      grantTypes,
      scopes,
      pkceRequired: true,
    }
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
