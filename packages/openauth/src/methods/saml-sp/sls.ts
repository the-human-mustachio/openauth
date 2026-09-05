/**
 * Single Logout Service — the inbound front-channel logout half.
 *
 * Mounted as a **public** (anonymous, flowless) route at
 * `GET|POST /m/<methodId>/sls` (declared in `AuthMethod.publicRoutes`
 * only when `SamlSpConfig.idp.sloUrl` is configured — advertising an
 * SLS we cannot complete would break interop, mirroring how
 * `unsolicitedCallback` is gated on `idpInitiated`).
 *
 * Authenticity here is **cryptographic, not cookie-based** — exactly
 * the SAML front-channel SLO model. node-saml verifies the inbound
 * message's XML-DSig against the pinned IdP cert (`SAML-AD1` — we do
 * not reimplement signature checking):
 *
 *   - **`SAMLRequest`** = an IdP-initiated `LogoutRequest`. Verify it,
 *     emit a signed `LogoutResponse` redirect back to the IdP's SLO
 *     endpoint, and return `MethodResult.challenge` carrying the
 *     verified `logout` intent so the framework fires
 *     `IdPOptions.onLogout` (host session teardown + optional
 *     `revokeAllForSubject`). The method stays port-free; the
 *     privileged side effect runs in the framework's public-route
 *     pipeline (see `ARCHITECTURE.md` §"onLogout + challenge.logout").
 *   - **`SAMLResponse`** = the IdP's `LogoutResponse` to an
 *     SP-initiated `LogoutRequest`. Validated and acknowledged here;
 *     the SP-initiated *send* path + post-logout redirect lands in the
 *     next increment.
 *
 * Verification failures are controlled `denied` (bad/absent signature,
 * unknown issuer, malformed message) — the same classification
 * `acs.ts` uses. Misconfiguration / infra faults are `error`.
 */
import { authError } from "../../types/error"
import type { MethodContext, MethodResult } from "../../types/method"
import { isErr } from "../../types/result"

import { buildSamlInstance, resolveSpEntityId } from "./saml-instance"
import type { SamlSpConfig, SamlSpProperties, SamlSpState } from "./types"

/** Minimal view of node-saml's `Profile` — never leaked publicly. */
type NodeSamlProfile = {
  nameID?: string
  sessionIndex?: string
  /** The inbound message's `ID` — used for front-channel replay dedup. */
  ID?: string
}

/**
 * Replay-dedup horizon for a verified `LogoutRequest`. A SAML
 * `LogoutRequest` usually carries no `NotOnOrAfter`, so unlike the
 * assertion path there is no message-supplied expiry to track — a
 * fixed, clamped window is sufficient (logout is idempotent; this only
 * suppresses a signed-message replay storm).
 */
const SLO_REPLAY_HORIZON_MS = 10 * 60_000

/**
 * The query string exactly as transmitted.
 *
 * The HTTP-Redirect binding signs the raw query octets (OASIS SAML 2.0
 * Bindings §3.4.4.1), so verification has to see the bytes the IdP
 * signed rather than a re-encoding of them.
 *
 * This used to read `new URL(request.url).search`, which round-trips the
 * query through whatever encoder the runtime ships. Whether that is
 * byte-preserving turns out to be a property of the *runtime*, not of
 * the request: it holds on Bun 1.1 and does not on Bun 1.4, where every
 * inbound redirect-binding logout became a 403 signature failure while
 * the POST binding — which never touches the query — kept working. The
 * local suite passed throughout, because it ran the older Bun.
 *
 * Slicing at the first `?` puts no encoder in the path, so it cannot
 * drift. A fragment is never transmitted to a server, but trimming one
 * is cheap insurance against a caller that synthesises a URL by hand.
 */
export function rawQueryString(requestUrl: string): string {
  const start = requestUrl.indexOf("?")
  if (start < 0) return ""
  const fragment = requestUrl.indexOf("#", start)
  return fragment < 0
    ? requestUrl.slice(start + 1)
    : requestUrl.slice(start + 1, fragment)
}

export async function consumeSls(
  ctx: MethodContext<SamlSpState>,
  methodId: string,
  config: SamlSpConfig,
): Promise<MethodResult<SamlSpProperties, SamlSpState>> {
  // Public route: no flow, but the HTTP layer supplies dispatch so we
  // can derive the stable SP entityID (same derivation as AuthnRequest
  // / ACS / metadata — no drift).
  if (!ctx.dispatch) {
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: /sls dispatched without issuer context (ctx.dispatch is null)",
      ),
    }
  }
  if (!config.idp.sloUrl) {
    // Should be unreachable: /sls is only public when sloUrl is set.
    return {
      kind: "error",
      error: authError.internalError(
        "saml-sp: /sls reached with no idp.sloUrl configured",
      ),
    }
  }

  const spEntityId = resolveSpEntityId(
    config,
    ctx.dispatch.issuerUrl,
    ctx.tenant.id,
    methodId,
  )

  // Read both bindings: HTTP-Redirect (GET, signed query string) and
  // HTTP-POST (form body). `url` is for reading individual parameters,
  // where decoding is what we want; the signature input must be the raw
  // transmitted bytes instead — see `rawQueryString`.
  const url = new URL(ctx.request.url)
  const originalQuery = rawQueryString(ctx.request.url)
  let samlRequest: string | null
  let samlResponse: string | null
  let relayState: string | null
  const isPost = ctx.request.method.toUpperCase() === "POST"
  let postForm: URLSearchParams | null = null
  try {
    if (isPost) {
      postForm = new URLSearchParams(await ctx.request.text())
      samlRequest = postForm.get("SAMLRequest")
      samlResponse = postForm.get("SAMLResponse")
      relayState = postForm.get("RelayState")
    } else {
      samlRequest = url.searchParams.get("SAMLRequest")
      samlResponse = url.searchParams.get("SAMLResponse")
      relayState = url.searchParams.get("RelayState")
    }
  } catch {
    return {
      kind: "error",
      error: authError.internalError("saml-sp: /sls could not read request"),
    }
  }

  if (!samlRequest && !samlResponse) {
    return { kind: "denied", reason: "missing SAMLRequest / SAMLResponse" }
  }

  // Building the verifier is a configuration concern (e.g. no IdP
  // signing cert within its validity window) — an operator fault, not a
  // per-user auth failure. Sign logout messages whenever a per-
  // connection SP key is configured (decoupled from `signAuthnRequest`,
  // which is specifically about the AuthnRequest).
  let saml: ReturnType<typeof buildSamlInstance>
  try {
    saml = buildSamlInstance(
      config,
      {
        spEntityId,
        acsUrl: ctx.dispatch.callbackUrl,
        scratch: ctx.methodScratch,
        logoutUrl: config.idp.sloUrl,
        logout: true,
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
  } catch (e) {
    return {
      kind: "error",
      error: authError.internalError(
        `saml-sp: cannot construct logout verifier: ${
          e instanceof Error ? e.message : String(e)
        }`,
        e,
      ),
    }
  }

  // ---- IdP-initiated LogoutRequest (the Phase 3 deliverable) --------
  if (samlRequest) {
    let profile: NodeSamlProfile | null
    try {
      const res = isPost
        ? await saml.validatePostRequestAsync({
            SAMLRequest: samlRequest,
            ...(relayState !== null ? { RelayState: relayState } : {}),
          })
        : await saml.validateRedirectAsync(
            Object.fromEntries(url.searchParams) as Record<string, string>,
            originalQuery,
          )
      profile = res.profile as NodeSamlProfile | null
    } catch (e) {
      // Bad/absent signature, unknown issuer, malformed LogoutRequest —
      // controlled, not a server fault. Same posture as the ACS.
      return {
        kind: "denied",
        reason: `logout request rejected: ${
          e instanceof Error ? e.message : String(e)
        }`,
      }
    }
    if (!profile) {
      return { kind: "denied", reason: "logout request produced no profile" }
    }
    // Fail-closed: the replay guard below is load-bearing (it stops a
    // captured validly-signed LogoutRequest from repeatedly driving
    // onLogout/revokeAllForSubject). node-saml v5.1.0 already throws
    // before returning a profile when `@ID` is absent, so this is
    // unreachable for a conformant message — but asserting it here
    // makes the documented fail-closed posture true in code rather
    // than silently dependent on an upstream library invariant
    // (mirrors the IdP-init assertion-replay handling in acs.ts).
    if (!profile.ID) {
      return {
        kind: "error",
        error: authError.internalError(
          "saml-sp: LogoutRequest carries no @ID — front-channel replay " +
            "protection cannot be established. Refusing to process.",
        ),
      }
    }

    // Front-channel replay dedup on the verified LogoutRequest @ID.
    // Logout is idempotent so the blast radius is low, but a replayed
    // signed message should not repeatedly drive revocation.
    {
      const key = `slo-replay:${profile.ID}`
      const seen = await ctx.methodScratch.get(key)
      if (seen.ok) {
        return {
          kind: "denied",
          reason: "logout request replay detected (request ID already seen)",
        }
      }
      const recorded = await ctx.methodScratch.put(
        key,
        "1",
        SLO_REPLAY_HORIZON_MS,
      )
      if (isErr(recorded)) {
        return {
          kind: "error",
          error: authError.internalError(
            "saml-sp: could not record LogoutRequest ID for replay protection",
          ),
        }
      }
    }

    // Emit the signed LogoutResponse redirect back to the IdP's SLO
    // endpoint (success status — we always honour a validly-signed
    // logout). node-saml uses `logoutUrl` (set above) as the target and
    // echoes `InResponseTo` from the request profile.
    let logoutResponseUrl: string
    try {
      logoutResponseUrl = await saml.getLogoutResponseUrlAsync(
        // node-saml's Profile shape; our minimal view is structurally
        // compatible for response generation (it reads ID / issuer).
        profile as never,
        relayState ?? "",
        {},
        true,
      )
    } catch (e) {
      return {
        kind: "error",
        error: authError.internalError(
          `saml-sp: failed to build LogoutResponse: ${
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
        headers: { location: logoutResponseUrl },
      }),
      // Triggers the framework's onLogout side effect (host teardown +
      // optional revokeAllForSubject) before the redirect is returned.
      logout: {
        ...(profile.nameID !== undefined ? { nameId: profile.nameID } : {}),
        ...(profile.sessionIndex !== undefined
          ? { sessionIndex: profile.sessionIndex }
          : {}),
      },
    }
  }

  // ---- IdP LogoutResponse (SP-initiated completion) ----------------
  // The SP-initiated *send* path + post-logout redirect lands in the
  // next increment; here we validate the IdP confirmed logout and
  // acknowledge. No `logout` side effect — SP-initiated revocation
  // happens at the trigger, not on the return leg.
  try {
    if (isPost) {
      await saml.validatePostResponseAsync({
        SAMLResponse: samlResponse as string,
        ...(relayState !== null ? { RelayState: relayState } : {}),
      })
    } else {
      await saml.validateRedirectAsync(
        Object.fromEntries(url.searchParams) as Record<string, string>,
        originalQuery,
      )
    }
  } catch (e) {
    return {
      kind: "denied",
      reason: `logout response rejected: ${
        e instanceof Error ? e.message : String(e)
      }`,
    }
  }

  return {
    kind: "challenge",
    response: new Response("Logged out.", {
      status: 200,
      headers: { "content-type": "text/plain" },
    }),
  }
}
