/**
 * SAML SP factory — `kind: "saml-sp"`.
 *
 * SCAFFOLD ONLY. The runtime implementation lands in SAML Phase 1
 * (see `docs/plans/claude/saml-sp-plan.md`). Today this file exists
 * to:
 *
 *   1. Reserve the `samlSpFactory` name in the public API.
 *   2. Lock in the type contract
 *      (`AuthMethodFactory<SamlSpProperties, SamlSpState, SamlSpConfig>`).
 *   3. Surface a clear runtime error when callers actually invoke
 *      `build` against this stub, naming the plan doc so the user can
 *      track when real support arrives.
 *
 * No `@node-saml/*` or `xml-crypto` imports appear here yet. Phase 1
 * adds them; the scaffold pre-locks the public-API leak guard so the
 * shape can't accidentally widen when those imports land.
 */
import type { v1 } from "@standard-schema/spec"

import type { AuthMethod, AuthMethodFactory } from "../../types/method"

import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

/**
 * Standard Schema v1 conformant stub. Phase 1 replaces this with a Zod
 * (or other StandardSchema v1) validator over the full `SamlSpConfig`
 * shape. The stub rejects everything so accidental use-before-impl
 * surfaces loudly rather than silently passing garbage through.
 */
const stubConfigSchema: v1.StandardSchema<unknown, SamlSpConfig> = {
  "~standard": {
    version: 1,
    vendor: "@_mustachio/openauth",
    validate: () => ({
      issues: [
        {
          message:
            "samlSpFactory is a scaffold; configuration validation is not yet implemented. See docs/plans/claude/saml-sp-plan.md.",
        },
      ],
    }),
  },
}

/**
 * Placeholder factory. Calling `build` throws — the framework refuses
 * to construct a SAML method instance until Phase 1 lands. Types are
 * locked in for downstream callers and for the public-API leak test.
 */
export const samlSpFactory: AuthMethodFactory<
  SamlSpProperties,
  SamlSpState,
  SamlSpConfig
> = {
  kind: "saml-sp",
  configSchema: stubConfigSchema,
  build: async (): Promise<
    AuthMethod<SamlSpProperties, SamlSpState>
  > => {
    throw new Error(
      "samlSpFactory.build: SAML SP is not yet implemented. " +
        "Track progress in docs/plans/claude/saml-sp-plan.md " +
        "(SAML Phase 1).",
    )
  },
}
