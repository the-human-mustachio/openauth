/**
 * Google — OIDC (auto-discovers `https://accounts.google.com`).
 *
 * Default scopes: `openid email profile`. Pass `hostedDomain` to restrict
 * to a Google Workspace domain.
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
  hostedDomain: z.string().optional(),
})

export const googleFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "google",
  configSchema: schema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> =>
    buildOidcMethod({
      id,
      kind,
      issuer: "https://accounts.google.com",
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "email", "profile"],
      ...(config.hostedDomain
        ? { extraAuthorizeParams: { hd: config.hostedDomain } }
        : {}),
    }),
}
