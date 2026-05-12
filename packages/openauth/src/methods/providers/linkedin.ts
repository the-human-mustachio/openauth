/**
 * LinkedIn — OAuth 2.0. Default scopes: `r_liteprofile r_emailaddress`.
 */
import { z } from "zod"

import { buildOauth2Method } from "../oauth2-generic"
import type { Oauth2Properties, Oauth2State } from "../oauth2-generic"
import type { AuthMethod, AuthMethodFactory } from "../../types/method"

const schema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  scopes: z.array(z.string()).optional(),
})

export const linkedinFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "linkedin",
  configSchema: schema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOauth2Method({
      id,
      kind,
      authorizationUrl: "https://www.linkedin.com/oauth/v2/authorization",
      tokenUrl: "https://www.linkedin.com/oauth/v2/accessToken",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["r_liteprofile", "r_emailaddress"],
    }),
}
