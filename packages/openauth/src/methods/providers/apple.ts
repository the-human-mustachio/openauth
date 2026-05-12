/**
 * Apple — OIDC. Auto-discovers from `https://appleid.apple.com`.
 *
 * Apple requires `response_mode=form_post` when `name` / `email` scopes
 * are requested. Pass `responseMode: "form_post"` when those scopes are
 * in play; default is `query`.
 */
import { z } from "zod"

import { buildOidcMethod } from "../oidc-generic"
import type { Oauth2Properties, Oauth2State } from "../oauth2-generic"
import type { AuthMethod, AuthMethodFactory } from "../../types/method"

const schema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  scopes: z.array(z.string()).optional(),
  responseMode: z.enum(["query", "form_post"]).optional(),
})

export const appleFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "apple",
  configSchema: schema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOidcMethod({
      id,
      kind,
      issuer: "https://appleid.apple.com",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "name", "email"],
      ...(config.responseMode ? { responseMode: config.responseMode } : {}),
    }),
}
