/**
 * Yahoo — OIDC. Default scopes: `openid email profile`.
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
  scopes: z.array(z.string()).optional(),
})

export const yahooFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "yahoo",
  configSchema: schema,
  build: async ({ id, kind, config }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOidcMethod({
      id,
      kind,
      issuer: "https://api.login.yahoo.com",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "email", "profile"],
    }),
}
