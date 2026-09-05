/**
 * SP-initiated Single Logout — the outbound half.
 *
 * `POST /m/<methodId>/logout` (public, gated on `idp.sloUrl` like
 * `/sls`). The **host** invokes this from its own logout UX for the
 * **already-authenticated** subject, supplying the subject's SAML
 * `NameID` (and, ideally, `SessionIndex`) — the values it received in
 * `SamlSpProperties` at login. The library does not persist the
 * NameID↔subject↔session mapping (the host owns it; see
 * `ARCHITECTURE.md` §"onLogout"), so the host is the only party that
 * can name who is logging out.
 *
 * Host contract / security:
 *   - This route only **propagates** logout to the upstream IdP. It
 *     does **not** revoke library tokens — OIDC session/token
 *     termination is `/end_session`'s job and is deliberately *not*
 *     auto-bridged. A complete host logout flow calls both.
 *   - It is `POST` (not `GET`) to keep a signed `LogoutRequest` off
 *     drive-by navigations / prefetch. It is still anonymous at the
 *     library boundary: the host MUST only render/trigger it for the
 *     authenticated subject, behind the host's own CSRF protection,
 *     with that subject's own `NameID`. A forced-logout via CSRF is a
 *     DoS-class risk the host owns (it owns the session); the library
 *     cannot authenticate the caller without owning a session it
 *     deliberately does not.
 *
 * The IdP processes the `LogoutRequest` and returns a `LogoutResponse`
 * to `/sls` (the response leg — see `sls.ts`).
 */
import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"

import {
  buildSamlInstance,
  resolveSpEntityId,
  NAME_ID_FORMAT_URN,
} from "./saml-instance"
import type {
  SamlNameIdFormat,
  SamlSpConfig,
  SamlSpProperties,
  SamlSpState,
} from "./types"

export async function initiateSpLogout(
  ctx: MethodContext<SamlSpState>,
  methodId: string,
  config: SamlSpConfig,
): Promise<MethodResult<SamlSpProperties, SamlSpState>> {
  if (!ctx.dispatch) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: /logout dispatched without issuer context (ctx.dispatch is null)",
      ),
    }
  }
  if (!config.idp.sloUrl) {
    // Unreachable: /logout is only public when sloUrl is set.
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: /logout reached with no idp.sloUrl configured",
      ),
    }
  }

  let nameId: string | null
  let sessionIndex: string | null
  let relayState: string | null
  let nameIdFormatParam: string | null
  try {
    const form = new URLSearchParams(await ctx.request.text())
    nameId = form.get("nameId")
    sessionIndex = form.get("sessionIndex")
    relayState = form.get("relayState")
    nameIdFormatParam = form.get("nameIdFormat")
  } catch {
    return {
      kind: "error",
      error: authError.internalError("saml-sp: /logout could not read POST body"),
    }
  }

  if (!nameId) {
    // The host must supply the subject's SAML NameID — the library
    // cannot derive it (it never persisted the mapping).
    return { kind: "denied", reason: "missing nameId" }
  }

  // NameID format: explicit param wins; else the connection's
  // configured format; else persistent (the SSO default). The param is
  // a friendly key (same vocabulary as `config.idp.nameIdFormat`), not
  // a raw URN — validate it rather than passing an arbitrary
  // host-supplied string straight into the LogoutRequest, where a
  // typo'd format silently produces a cryptic IdP-side rejection.
  if (
    nameIdFormatParam !== null &&
    !(nameIdFormatParam in NAME_ID_FORMAT_URN)
  ) {
    return {
      kind: "denied",
      reason:
        `unrecognized nameIdFormat "${nameIdFormatParam}" — expected one ` +
        `of: ${Object.keys(NAME_ID_FORMAT_URN).join(", ")}`,
    }
  }
  const nameIDFormat =
    nameIdFormatParam !== null
      ? NAME_ID_FORMAT_URN[nameIdFormatParam as SamlNameIdFormat]
      : config.idp.nameIdFormat !== undefined
        ? NAME_ID_FORMAT_URN[config.idp.nameIdFormat]
        : NAME_ID_FORMAT_URN.persistent

  const spEntityId = resolveSpEntityId(
    config,
    ctx.dispatch.issuerUrl,
    ctx.tenant.id,
    methodId,
  )

  let redirectUrl: string
  try {
    const saml = buildSamlInstance(
      config,
      {
        spEntityId,
        acsUrl: ctx.dispatch.callbackUrl,
        scratch: ctx.methodScratch,
        logoutUrl: config.idp.sloUrl,
        logout: true,
        // Sign the LogoutRequest whenever a per-connection SP key is
        // configured — most IdPs require a signed SP-initiated logout.
        ...(config.signingKey
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
    redirectUrl = await saml.getLogoutUrlAsync(
      // node-saml's Profile shape; structurally compatible for request
      // generation (it reads nameID / nameIDFormat / sessionIndex).
      {
        nameID: nameId,
        nameIDFormat: nameIDFormat,
        ...(sessionIndex !== null ? { sessionIndex } : {}),
      } as never,
      relayState ?? "",
      {},
    )
  } catch (e) {
    return {
      kind: "error",
      error: authError.internalError(
        `saml-sp: failed to build LogoutRequest: ${
          e instanceof Error ? e.message : String(e)
        }`,
        e,
      ),
    }
  }

  // Pure protocol propagation — no `logout` side effect (the host
  // already tore down its session and, separately, calls /end_session
  // for OIDC token revocation).
  return {
    kind: "challenge",
    response: new Response(null, {
      status: 302,
      headers: { location: redirectUrl },
    }),
  }
}
