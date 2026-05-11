/**
 * Microsoft — OIDC, tenant-templated. The `tenant` field is `"common"`,
 * `"organizations"`, `"consumers"`, or a specific Entra tenant id /
 * domain.
 *
 * Discovery is fetched per tenant; the result is cached inside the
 * `MethodCache` so subsequent flows skip the round trip.
 */
import { z } from "zod"

import { buildOidcMethod } from "../oidc-generic"
import type {
  Oauth2Properties,
  Oauth2State,
} from "../oauth2-generic"
import type { AuthMethod, AuthMethodFactory } from "../../types/method"

const schema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  tenant: z.string().optional(),
  scopes: z.array(z.string()).optional(),
})

export const microsoftFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "microsoft",
  configSchema: schema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOidcMethod({
      id,
      kind,
      issuer: `https://login.microsoftonline.com/${config.tenant ?? "common"}/v2.0`,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "email", "profile"],
    }),
}
