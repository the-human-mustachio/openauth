/**
 * Slack — Sign in with Slack (OpenID Connect on Slack's own endpoints).
 * Slack ships an id_token at the token endpoint; we treat it as OIDC.
 *
 * Default scopes: `openid email profile`.
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

export const slackFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "slack",
  configSchema: schema,
  build: async ({ id, kind, config }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOauth2Method({
      id,
      kind,
      authorizationUrl: "https://slack.com/openid/connect/authorize",
      tokenUrl: "https://slack.com/api/openid.connect.token",
      jwksUri: "https://slack.com/openid/connect/keys",
      expectedIssuer: "https://slack.com",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "email", "profile"],
    }),
}
