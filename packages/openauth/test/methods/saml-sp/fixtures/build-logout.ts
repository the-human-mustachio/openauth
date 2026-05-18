/**
 * SAML front-channel `LogoutRequest` fixture builder (IdP → SP).
 *
 * As with `build-response.ts`, signing uses node-saml's own
 * primitives so a fixture only ever exercises the property under test,
 * never an incidental canonicalization mismatch:
 *
 *   - **Redirect binding** — a node-saml `SAML` instance is driven in
 *     "IdP role" (`privateKey = IDP_KEY`, `issuer = idpEntityId`) and
 *     its `getLogoutUrlAsync` produces a real signed redirect query.
 *     This is exactly the byte sequence our SP's `validateRedirectAsync`
 *     verifies.
 *   - **POST binding** — a `<samlp:LogoutRequest>` is signed with
 *     `signSamlPost`, the same path `build-response.ts` uses.
 *
 * `wrongKey` signs with the attacker keypair (SP trusts `IDP_CERT`) to
 * drive a deterministic verification failure.
 */
// Deep imports — node-saml ships no `exports` map, so `lib/*` resolves
// and carries co-located .d.ts. Test-only.
import nodeSaml from "@node-saml/node-saml"
import { signSamlPost } from "@node-saml/node-saml/lib/saml-post-signing"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const { SAML } = nodeSaml

const F = (n: string) => readFileSync(join(import.meta.dir, n), "utf8")

export const IDP_CERT = F("idp-cert.pem")
const IDP_KEY = F("idp-key.pem")
const ATTACKER_CERT = F("attacker-cert.pem")
const ATTACKER_KEY = F("attacker-key.pem")

export type LogoutOpts = {
  idpEntityId: string
  /** The SP's own SLS URL (LogoutRequest `Destination`). */
  slsUrl: string
  nameId?: string
  sessionIndex?: string
  relayState?: string
  /** Sign with the attacker key (SP trusts IDP_CERT) → must be denied. */
  wrongKey?: boolean
  /** Override the request ID (replay tests reuse one). */
  requestId?: string
}

const iso = (ms: number) => new Date(ms).toISOString()

/**
 * Redirect-binding LogoutRequest. Returns the **query string** (no
 * leading `?`) — `SAMLRequest`, `RelayState?`, `SigAlg`, `Signature` —
 * exactly as an IdP front-channel SLO redirect would carry it.
 */
export async function redirectLogoutRequest(
  opts: LogoutOpts,
): Promise<string> {
  const idp = new SAML({
    // Mandatory ctor fields (unused for request generation).
    idpCert: IDP_CERT,
    issuer: opts.idpEntityId,
    callbackUrl: opts.slsUrl,
    // node-saml asserts `entryPoint` before switching the redirect
    // target to `logoutUrl` — set both (we only keep the query string).
    entryPoint: opts.slsUrl,
    logoutUrl: opts.slsUrl,
    privateKey: opts.wrongKey ? ATTACKER_KEY : IDP_KEY,
    publicCert: opts.wrongKey ? ATTACKER_CERT : IDP_CERT,
    signatureAlgorithm: "sha256",
  })
  const url = await idp.getLogoutUrlAsync(
    {
      nameID: opts.nameId ?? "user-persistent-id-001",
      nameIDFormat:
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
      ...(opts.sessionIndex !== undefined
        ? { sessionIndex: opts.sessionIndex }
        : {}),
    } as never,
    opts.relayState ?? "",
    {},
  )
  return new URL(url).search.replace(/^\?/, "")
}

/**
 * POST-binding LogoutRequest. Returns the base64 `SAMLRequest` form
 * value (signature embedded in the XML).
 */
export function postLogoutRequest(opts: LogoutOpts): string {
  const now = Date.now()
  const id = opts.requestId ?? "_lr_" + Math.random().toString(36).slice(2)
  const nameId = opts.nameId ?? "user-persistent-id-001"
  const sessionIndexEl =
    opts.sessionIndex !== undefined
      ? `<samlp:SessionIndex>${opts.sessionIndex}</samlp:SessionIndex>`
      : ""
  const xml =
    `<samlp:LogoutRequest ` +
    `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${id}" Version="2.0" IssueInstant="${iso(now)}" ` +
    `Destination="${opts.slsUrl}">` +
    `<saml:Issuer>${opts.idpEntityId}</saml:Issuer>` +
    `<saml:NameID ` +
    `Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` +
    `${nameId}</saml:NameID>` +
    sessionIndexEl +
    `</samlp:LogoutRequest>`

  const signed = signSamlPost(
    xml,
    '/*[local-name(.)="LogoutRequest"]',
    {
      privateKey: opts.wrongKey ? ATTACKER_KEY : IDP_KEY,
      publicCert: opts.wrongKey ? ATTACKER_CERT : IDP_CERT,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    },
  )
  return Buffer.from(signed, "utf8").toString("base64")
}

export type LogoutResponseOpts = {
  idpEntityId: string
  /** The SP's own SLS URL (LogoutResponse `Destination`). */
  slsUrl: string
  /** `InResponseTo` — the SP `LogoutRequest` ID being answered. */
  inResponseTo?: string
  /** Non-Success top-level status (IdP refused / partial logout). */
  failure?: boolean
  /** Sign with the attacker key (SP trusts IDP_CERT) → must be denied. */
  wrongKey?: boolean
}

/**
 * POST-binding `LogoutResponse` (IdP → SP, the SP-initiated return
 * leg). node-saml requires a valid **document-level** signature on a
 * `LogoutResponse` (saml.js: `if (!validSignature) throw`), so it is
 * signed at the `LogoutResponse` root, not a child.
 */
export function postLogoutResponse(opts: LogoutResponseOpts): string {
  const now = Date.now()
  const id = "_lresp_" + Math.random().toString(36).slice(2)
  const status = opts.failure
    ? "urn:oasis:names:tc:SAML:2.0:status:Responder"
    : "urn:oasis:names:tc:SAML:2.0:status:Success"
  const xml =
    `<samlp:LogoutResponse ` +
    `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${id}" Version="2.0" IssueInstant="${iso(now)}" ` +
    `Destination="${opts.slsUrl}"` +
    (opts.inResponseTo ? ` InResponseTo="${opts.inResponseTo}"` : "") +
    `>` +
    `<saml:Issuer>${opts.idpEntityId}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
    `</samlp:LogoutResponse>`

  const signed = signSamlPost(
    xml,
    '/*[local-name(.)="LogoutResponse"]',
    {
      privateKey: opts.wrongKey ? ATTACKER_KEY : IDP_KEY,
      publicCert: opts.wrongKey ? ATTACKER_CERT : IDP_CERT,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    },
  )
  return Buffer.from(signed, "utf8").toString("base64")
}
