/**
 * Facebook — OAuth 2.0. Default scopes: `email public_profile`.
 *
 * Facebook also exposes an OIDC discovery doc at
 * `https://graph.facebook.com`, but the canonical app integration uses
 * the OAuth 2.0 endpoints below. Pass `useOidc: true` to switch to OIDC.
 */
import { z } from "zod"

import { buildOauth2Method } from "../oauth2-generic"
import { buildOidcMethod } from "../oidc-generic"
import type { Oauth2Properties, Oauth2State } from "../oauth2-generic"
import type { AuthMethod, AuthMethodFactory } from "../../types/method"

const schema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  scopes: z.array(z.string()).optional(),
  useOidc: z.boolean().optional(),
})

export const facebookFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "facebook",
  configSchema: schema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> => {
    if (config.useOidc) {
      return buildOidcMethod({
        id,
        kind,
        issuer: "https://graph.facebook.com",
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        scopes: config.scopes ?? ["openid", "email", "public_profile"],
      })
    }
    return buildOauth2Method({
      id,
      kind,
      authorizationUrl: "https://www.facebook.com/v12.0/dialog/oauth",
      tokenUrl: "https://graph.facebook.com/v12.0/oauth/access_token",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["email", "public_profile"],
    })
  },
}
