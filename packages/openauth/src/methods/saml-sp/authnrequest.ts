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
import { isErr } from "../../types/result"

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

  // O3: signed AuthnRequest uses a per-connection SP keypair from
  // config (decoupled from the OIDC KeyStore). The Zod schema already
  // enforces `signAuthnRequest ⇒ signingKey`; guard defensively so a
  // schema regression can never silently emit an unsigned request when
  // the operator asked for a signed one.
  if (config.signAuthnRequest && !config.signingKey) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: signAuthnRequest is true but signingKey is missing " +
          "(config schema should have rejected this).",
      ),
    }
  }

  const spEntityId = deriveSpEntityId(
    ctx.dispatch.issuerUrl,
    ctx.tenant.id,
    methodId,
  )

  const acsUrl = ctx.dispatch.callbackUrl

  // Fail fast if the SessionStore adapter doesn't implement the
  // scratch trio. node-saml ignores its CacheProvider.saveAsync
  // return value, so without this probe we would issue an
  // AuthnRequest whose request id is never cached — every assertion
  // would then be rejected at the ACS with an opaque
  // "InResponseTo not valid", and the operator would have no signal
  // that the real problem is an unsupported adapter. Mirrors the
  // explicit signAuthnRequest guard above.
  const probe = await ctx.methodScratch.put(
    "authnrequest-scratch-probe",
    "1",
    1000,
  )
  if (isErr(probe)) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: the configured SessionStore adapter does not support " +
          "methodScratch (saveScratch/readScratch/deleteScratch), which " +
          "SAML SP requires for InResponseTo replay protection. Deploy " +
          "SAML against an adapter that implements the scratch trio.",
      ),
    }
  }

  let redirectUrl: string
  try {
    const saml = buildSamlInstance(
      config,
      {
        spEntityId,
        acsUrl,
        scratch: ctx.methodScratch,
        ...(config.signAuthnRequest && config.signingKey
          ? {
              signing: {
                privateKeyPem: config.signingKey.privateKeyPem,
                certPem: config.signingKey.certPem,
              },
            }
          : {}),
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
