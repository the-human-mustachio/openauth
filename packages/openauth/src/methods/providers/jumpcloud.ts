/**
 * JumpCloud — OIDC, fully spec-compliant discovery doc.
 */
import { z } from "zod"

import { buildOidcMethod } from "../oidc-generic"
import type { Oauth2Properties, Oauth2State } from "../oauth2-generic"
import type { AuthMethod, AuthMethodFactory } from "../../types/method"

const schema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  scopes: z.array(z.string()).optional(),
})

export const jumpcloudFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "jumpcloud",
  configSchema: schema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOidcMethod({
      id,
      kind,
      issuer: "https://oauth.id.jumpcloud.com",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "email", "profile"],
    }),
}
