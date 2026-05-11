/**
 * AWS Cognito — OIDC. The `domain` is the Cognito user-pool domain
 * (without protocol), e.g. `"my-pool.auth.us-east-1.amazoncognito.com"`.
 *
 * Cognito's OIDC discovery is at
 * `https://cognito-idp.<region>.amazonaws.com/<userPoolId>/.well-known/openid-configuration`
 * (NOT the user-pool domain). Callers supply the user-pool domain for the
 * OAuth endpoints AND the issuer URL for discovery / id_token validation.
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
  clientSecret: z.string().optional(),
  /** Cognito user-pool hosted UI domain (no protocol). */
  domain: z.string(),
  /** Issuer URL, e.g. `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xyz`. */
  issuer: z.string(),
  scopes: z.array(z.string()).optional(),
})

export const cognitoFactory: AuthMethodFactory<
  Oauth2Properties,
  Oauth2State,
  z.infer<typeof schema>
> = {
  kind: "cognito",
  configSchema: schema,
  build: async ({ id, kind, config }): Promise<AuthMethod<Oauth2Properties, Oauth2State>> => {
    return buildOidcMethod({
      id,
      kind,
      issuer: config.issuer,
      // Cognito's hosted UI endpoints are separate from its discovery doc.
      // Pin them explicitly so we don't double-fetch.
      endpoints: {
        authorization_endpoint: `https://${config.domain}/oauth2/authorize`,
        token_endpoint: `https://${config.domain}/oauth2/token`,
        jwks_uri: `${config.issuer.replace(/\/+$/, "")}/.well-known/jwks.json`,
        issuer: config.issuer,
      },
      clientId: config.clientId,
      ...(config.clientSecret ? { clientSecret: config.clientSecret } : {}),
      scopes: config.scopes ?? ["openid", "email", "profile"],
    })
  },
}
