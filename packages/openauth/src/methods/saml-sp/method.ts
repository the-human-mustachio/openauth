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
        consumeAssertion(ctx, config),
    },
  }
}
