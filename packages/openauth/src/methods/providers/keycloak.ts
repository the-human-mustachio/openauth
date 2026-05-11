/**
 * Keycloak — OIDC, per-realm. Issuer is templated from `baseUrl` + `realm`.
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
  /** Keycloak base URL, e.g. `https://auth.example.com`. */
  baseUrl: z.string(),
  /** Realm name, e.g. `"acme"`. */
  realm: z.string(),
  scopes: z.array(z.string()).optional(),
})

export const keycloakFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "keycloak",
  configSchema: schema,
  build: async ({ id, kind, config }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> => {
    const base = config.baseUrl.replace(/\/+$/, "")
    return buildOidcMethod({
      id,
      kind,
      issuer: `${base}/realms/${config.realm}`,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes ?? ["openid", "email", "profile"],
    })
  },
}
