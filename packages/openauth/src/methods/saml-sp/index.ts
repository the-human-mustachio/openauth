/**
 * `@_mustachio/openauth/methods/saml-sp` — SAML 2.0 Service Provider
 * method family.
 *
 * **Node-only.** This entry depends transitively on
 * `@node-saml/node-saml` and `xml-crypto`, which require `node:crypto`
 * and the `@xmldom/xmldom` DOM. Cloudflare Workers, browsers, and
 * other edge runtimes cannot load this module; use the root
 * `@_mustachio/openauth` entry (OIDC / OAuth methods) on those
 * platforms.
 *
 * The library's root entry is verified edge-clean by
 * `test/types/public-api-no-thirdparty-leaks.test.ts` and the
 * complementary `saml-sp-no-thirdparty-leaks.test.ts` — neither this
 * subpath's third-party deps nor its public types are reachable from
 * `@_mustachio/openauth`.
 *
 * See `docs/plans/claude/saml-sp-plan.md` for the architectural
 * decisions backing this surface (SAML-AD1–AD7) and the phase plan.
 *
 * Status: scaffold. Phase 1 implementation pending.
 */
export { samlSpFactory } from "./factory"

export type {
  SamlAttributeMapping,
  SamlAttributeRef,
  SamlIdpConfig,
  SamlIdpInitiatedConfig,
  SamlIdpSigningCert,
  SamlNameIdFormat,
  SamlSpConfig,
  SamlSpProperties,
  SamlSpState,
} from "./types"
