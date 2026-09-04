/**
 * Cert-rotation shim.
 *
 * `@node-saml/node-saml`'s `idpCert` accepts a single PEM, an array of
 * PEMs, or a callback. Our config models hot rotation as an array of
 * `{ pem, notBefore?, notAfter? }`. This pure function filters that
 * array to the certs whose validity window covers `now`, producing the
 * PEM list node-saml verifies against.
 *
 * A cert with no `notBefore` has no lower bound; no `notAfter` has no
 * upper bound. `notBefore` is inclusive, `notAfter` is exclusive — a
 * cert is active while `notBefore <= now < notAfter`. Overlapping
 * windows are the whole point: during rotation both the outgoing and
 * incoming cert are active so in-flight assertions from either key
 * still verify.
 *
 * Returns `[]` when nothing is in window — the caller surfaces a
 * configuration error rather than handing node-saml an empty cert set
 * (which it would treat as "accept nothing").
 */
import type { SamlIdpSigningCert } from "./types"

export function selectActiveCertPems(
  certs: ReadonlyArray<SamlIdpSigningCert>,
  nowMs: number,
): string[] {
  return certs
    .filter((c) => {
      if (c.notBefore !== undefined && nowMs < c.notBefore) return false
      if (c.notAfter !== undefined && nowMs >= c.notAfter) return false
      return true
    })
    .map((c) => c.pem)
}
