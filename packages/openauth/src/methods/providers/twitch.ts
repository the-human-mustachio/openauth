/**
 * Twitch — OAuth 2.0 (Twitch supports OIDC but uses OAuth flows by
 * default). Default scopes: `user:read:email`.
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

export const twitchFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "twitch",
  configSchema: schema,
  build: async ({ id, kind, config }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOauth2Method({
      id,
      kind,
      authorizationUrl: "https://id.twitch.tv/oauth2/authorize",
      tokenUrl: "https://id.twitch.tv/oauth2/token",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["user:read:email"],
    }),
}
