/**
 * Encrypted-assertion fixture.
 *
 * Builds a normal **signed** Response with `buildSamlResponse` (the
 * decrypted assertion must still carry a valid XML-DSig — node-saml
 * enforces `wantAssertionsSigned` *after* decryption), then replaces
 * the plaintext `<saml:Assertion>` with a `<saml:EncryptedAssertion>`
 * encrypted to the SP's cert using node-saml's own `xml-encryption`
 * dependency (so the only thing exercised is decryption, not an
 * incidental algorithm mismatch).
 *
 * The fixture reuses the existing IdP keypair as the SP
 * encryption/decryption pair (a valid RSA pair): the test configures
 * `decryptionKey = { privateKeyPem: IDP_KEY, certPem: IDP_CERT }` and
 * this encrypts to `IDP_CERT`'s public key.
 */
import xmlenc from "xml-encryption"
import { createPublicKey } from "node:crypto"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { buildSamlResponse, type BuildOpts } from "./build-response"

const F = (n: string) => readFileSync(join(import.meta.dir, n), "utf8")

/** The SP decryption pair the test wires into `config.decryptionKey`. */
export const DECRYPTION_PRIVATE_KEY = F("idp-key.pem")
export const DECRYPTION_CERT = F("idp-cert.pem")

function encryptXml(
  content: string,
  options: Parameters<typeof xmlenc.encrypt>[1],
): Promise<string> {
  return new Promise((resolve, reject) => {
    xmlenc.encrypt(content, options, (err, res) =>
      err ? reject(err) : resolve(res as string),
    )
  })
}

const ASSERTION_RE = /<saml:Assertion[\s\S]*?<\/saml:Assertion>/

/**
 * Produce a base64 SAML Response whose (signed) assertion is wrapped in
 * `<saml:EncryptedAssertion>`. `opts` is the same `BuildOpts` as
 * `buildSamlResponse` (so the underlying assertion is valid + signed).
 */
export async function buildEncryptedSamlResponse(
  opts: BuildOpts,
): Promise<string> {
  const xml = Buffer.from(buildSamlResponse(opts), "base64").toString(
    "utf8",
  )
  const m = xml.match(ASSERTION_RE)
  if (!m) throw new Error("fixture: no <saml:Assertion> to encrypt")

  const rsaPub = createPublicKey(DECRYPTION_CERT)
    .export({ type: "spki", format: "pem" })
    .toString()

  const encryptedData = await encryptXml(m[0], {
    rsa_pub: rsaPub,
    pem: DECRYPTION_CERT,
    encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    keyEncryptionAlgorithm:
      "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
  })

  const wrapped =
    `<saml:EncryptedAssertion ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
    encryptedData +
    `</saml:EncryptedAssertion>`

  return Buffer.from(xml.replace(m[0], wrapped), "utf8").toString(
    "base64",
  )
}
