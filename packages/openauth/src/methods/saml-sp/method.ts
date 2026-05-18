/**
 * `buildSamlSpMethod` — assembles the `AuthMethod` for a SAML SP
 * instance. Mirrors `buildOauth2Method`: data + handler functions, no
 * framework imports beyond `types/`.
 *
 * Routes:
 *   - `GET /authorize`  → SP-initiated AuthnRequest redirect (implemented).
 *   - `GET /callback`   → ACS verification gauntlet (next increment).
 *
 * The framework's universal callback (`/cb/<methodId>`, both GET and
 * POST) always dispatches the `"GET /callback"` route key, so the ACS
 * lives there rather than at a bespoke `/acs` sub-path.
 */
import type { AuthMethod, MethodContext } from "../../types/method"

import { consumeAssertion } from "./acs"
import { buildAuthnRequestRedirect } from "./authnrequest"
import { buildSpMetadata } from "./metadata"
import { consumeSls } from "./sls"
import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

export function buildSamlSpMethod(
  id: string,
  kind: string,
  config: SamlSpConfig,
): AuthMethod<SamlSpProperties, SamlSpState> {
  return {
    id,
    kind,
    type: "custom",
    routes: {
      "GET /authorize": (ctx: MethodContext<SamlSpState>) =>
        buildAuthnRequestRedirect(ctx, id, config),
      "GET /callback": (ctx: MethodContext<SamlSpState>) =>
        consumeAssertion(ctx, id, config),
      "GET /metadata": (ctx: MethodContext<SamlSpState>) =>
        buildSpMetadata(ctx, id, config),
      // Front-channel Single Logout (both bindings). Verified by
      // XML-DSig, not a flow cookie — see sls.ts.
      "GET /sls": (ctx: MethodContext<SamlSpState>) =>
        consumeSls(ctx, id, config),
      "POST /sls": (ctx: MethodContext<SamlSpState>) =>
        consumeSls(ctx, id, config),
    },
    // Anonymous, no flow cookie. `/metadata` always; `/sls` only when
    // an IdP SLO endpoint is configured — advertising an SLS we cannot
    // complete a round-trip on would break interop (same conservative
    // gating as `unsolicitedCallback` ⇐ `idpInitiated`).
    publicRoutes: [
      "GET /metadata",
      ...(config.idp.sloUrl
        ? (["GET /sls", "POST /sls"] as const)
        : ([] as const)),
    ],
    // IdP-initiated SSO: only when this instance is configured for it.
    // Absent ⇒ unsolicited Responses stay invalid_request.
    unsolicitedCallback: config.idpInitiated !== undefined,
  }
}
