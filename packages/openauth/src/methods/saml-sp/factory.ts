/**
 * SAML SP factory — `kind: "saml-sp"`.
 *
 * Parallels `oauth2Factory` / `oidcFactory`: a Zod `configSchema`
 * validates the tenant-supplied `SamlSpConfig` blob (Zod 3.24+ is
 * Standard Schema v1 conformant, so it satisfies
 * `AuthMethodFactory.configSchema` directly), and `build` delegates to
 * `buildSamlSpMethod`.
 *
 * No `@node-saml/*` import appears here — node-saml is reached only at
 * request time inside the route handlers, so importing the factory
 * type surface stays cheap and the public-API leak guard stays green.
 */
import { z } from "zod"

import type { AuthMethod, AuthMethodFactory } from "../../types/method"

import { buildSamlSpMethod } from "./method"
import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

const attributeRefSchema = z.union([
  z.object({ source: z.literal("nameId") }),
  z.object({
    source: z.literal("attribute"),
    name: z.string().min(1),
    format: z.string().optional(),
  }),
])

const attributeMappingSchema = z.object({
  subject: attributeRefSchema.optional(),
  email: attributeRefSchema.optional(),
  emailVerified: z
    .object({ source: z.literal("literal"), value: z.boolean() })
    .optional(),
  name: attributeRefSchema.optional(),
  groups: attributeRefSchema.optional(),
  custom: z.record(attributeRefSchema).optional(),
})

const signingCertSchema = z.object({
  pem: z.string().min(1),
  notBefore: z.number().optional(),
  notAfter: z.number().optional(),
})

const idpSchema = z.object({
  entityId: z.string().min(1),
  ssoUrl: z.string().url(),
  sloUrl: z.string().url().optional(),
  nameIdFormat: z
    .enum(["persistent", "transient", "emailAddress", "unspecified"])
    .optional(),
  signingCerts: z.array(signingCertSchema).min(1),
})

const idpInitiatedSchema = z.object({
  defaultClientId: z.string().min(1),
  defaultRedirectUri: z.string().url(),
  defaultScopes: z.array(z.string()).optional(),
})

const samlSpConfigSchema = z
  .object({
    idp: idpSchema,
    attributeMapping: attributeMappingSchema,
    signAuthnRequest: z.boolean().optional(),
    signingKey: z
      .object({
        privateKeyPem: z.string().min(1),
        certPem: z.string().min(1),
      })
      .optional(),
    allowEncryptedAssertions: z.boolean().optional(),
    decryptionKey: z
      .object({
        privateKeyPem: z.string().min(1),
        certPem: z.string().min(1),
      })
      .optional(),
    idpInitiated: idpInitiatedSchema.optional(),
    clockSkewSeconds: z.number().int().nonnegative().optional(),
  })
  .refine((c) => !c.signAuthnRequest || c.signingKey !== undefined, {
    message: "signingKey is required when signAuthnRequest is true",
    path: ["signingKey"],
  })
  .refine(
    (c) => !c.allowEncryptedAssertions || c.decryptionKey !== undefined,
    {
      message:
        "decryptionKey is required when allowEncryptedAssertions is true",
      path: ["decryptionKey"],
    },
  )

export type SamlSpFactoryConfig = z.infer<typeof samlSpConfigSchema>

/**
 * Generic SAML 2.0 Service Provider factory.
 *
 * `kind: "saml-sp"`. Use a distinct `MethodConfig.id` per upstream IdP
 * to register multiple SAML connections against a single tenant.
 */
export const samlSpFactory: AuthMethodFactory<
  SamlSpProperties,
  SamlSpState,
  SamlSpConfig
> = {
  kind: "saml-sp",
  configSchema: samlSpConfigSchema,
  build: async ({
    id,
    kind,
    config,
  }): Promise<AuthMethod<SamlSpProperties, SamlSpState>> =>
    buildSamlSpMethod(id, kind, config),
}
