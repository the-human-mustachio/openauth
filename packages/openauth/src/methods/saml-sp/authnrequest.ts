/**
 * `GET /authorize` — SP-initiated SSO. Builds a SAML `AuthnRequest`
 * via node-saml and redirects the user agent to the IdP's SSO
 * endpoint (HTTP-Redirect binding).
 *
 * The framework state envelope (`ctx.dispatch.state`) is carried as
 * RelayState; the IdP echoes it back on the ACS POST so the standard
 * callback machinery can recover the tenant + flow. node-saml records
 * the generated request id in the `methodScratch`-backed cache for
 * `InResponseTo` enforcement at the ACS.
 */
import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"

import { buildSamlInstance, deriveSpEntityId } from "./saml-instance"
import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

export async function buildAuthnRequestRedirect(
  ctx: MethodContext<SamlSpState>,
  methodId: string,
  config: SamlSpConfig,
): Promise<MethodResult<SamlSpProperties, SamlSpState>> {
  if (!ctx.dispatch) {
    return {
      kind: "error",
      error: authError.internalError("saml-sp: dispatch missing on /authorize"),
    }
  }

  // AuthnRequest signing needs a KeyStore-resolved private key, which
  // is not yet threaded into MethodContext. Reject explicitly rather
  // than silently emit an unsigned request when the operator asked for
  // a signed one.
  if (config.signAuthnRequest) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: signAuthnRequest is not yet implemented (KeyStore wiring " +
          "lands in a later SAML Phase 1 increment). Track in " +
          "docs/plans/claude/saml-sp-plan.md.",
      ),
    }
  }

  const spEntityId = deriveSpEntityId(
    ctx.dispatch.issuerUrl,
    ctx.tenant.id,
    methodId,
  )

  const acsUrl = ctx.dispatch.callbackUrl

  let redirectUrl: string
  try {
    const saml = buildSamlInstance(
      config,
      {
        spEntityId,
        acsUrl,
        scratch: ctx.methodScratch,
      },
      Date.now(),
    )
    redirectUrl = await saml.getAuthorizeUrlAsync(
      ctx.dispatch.state,
      undefined,
      {},
    )
  } catch (e) {
    return {
      kind: "error",
      error: authError.internalError(
        `saml-sp: failed to build AuthnRequest: ${
          e instanceof Error ? e.message : String(e)
        }`,
        e,
      ),
    }
  }

  return {
    kind: "challenge",
    response: new Response(null, {
      status: 302,
      headers: { location: redirectUrl },
    }),
    saveMethodState: {
      relayState: ctx.dispatch.state,
      issuedAt: Date.now(),
      spEntityId,
      acsUrl,
    },
  }
}
