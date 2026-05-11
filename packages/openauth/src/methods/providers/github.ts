/**
 * GitHub — OAuth 2.0. No id_token; user info via the REST API in the
 * `success` callback if needed.
 *
 * Default scopes: `read:user user:email`.
 */
import { z } from "zod"

import { buildOauth2Method } from "../oauth2-generic"
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

export const githubFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "github",
  configSchema: schema,
  build: async ({ id, kind, config }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOauth2Method({
      id,
      kind,
      authorizationUrl: "https://github.com/login/oauth/authorize",
      tokenUrl: "https://github.com/login/oauth/access_token",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["read:user", "user:email"],
      // GitHub doesn't accept PKCE on the standard OAuth flow.
      pkce: "none",
    }),
}
