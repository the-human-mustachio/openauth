/**
 * SAML SP factory config validation. The factory's `configSchema` is
 * the boundary where tenant-supplied SAML config is accepted or
 * rejected before any node-saml code runs.
 */
import { describe, expect, test } from "bun:test"

import { samlSpFactory } from "../../../src/methods/saml-sp/factory"

function validate(input: unknown) {
  return samlSpFactory.configSchema["~standard"].validate(input)
}

const VALID = {
  idp: {
    entityId: "https://idp.example/saml/metadata",
    ssoUrl: "https://idp.example/saml/sso",
    nameIdFormat: "persistent",
    signingCerts: [{ pem: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----" }],
  },
  attributeMapping: {
    subject: { source: "nameId" },
    email: { source: "attribute", name: "email" },
    emailVerified: { source: "literal", value: true },
  },
}

describe("samlSpFactory.configSchema", () => {
  test("accepts a minimal valid config", async () => {
    const r = await validate(VALID)
    expect("issues" in r && r.issues).toBeFalsy()
  })

  test("rejects missing signingCerts", async () => {
    const bad = { ...VALID, idp: { ...VALID.idp, signingCerts: [] } }
    const r = await validate(bad)
    expect("issues" in r && (r.issues?.length ?? 0) > 0).toBe(true)
  })

  test("rejects a non-URL ssoUrl", async () => {
    const bad = { ...VALID, idp: { ...VALID.idp, ssoUrl: "not-a-url" } }
    const r = await validate(bad)
    expect("issues" in r && (r.issues?.length ?? 0) > 0).toBe(true)
  })

  test("rejects signAuthnRequest:true without signingKey", async () => {
    const bad = { ...VALID, signAuthnRequest: true }
    const r = await validate(bad)
    expect("issues" in r && (r.issues?.length ?? 0) > 0).toBe(true)
  })

  test("accepts signAuthnRequest:true with a per-connection signingKey (O3)", async () => {
    const ok = {
      ...VALID,
      signAuthnRequest: true,
      signingKey: {
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
        certPem: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
      },
    }
    const r = await validate(ok)
    expect("issues" in r && r.issues).toBeFalsy()
  })

  test("rejects a signingKey missing certPem", async () => {
    const bad = {
      ...VALID,
      signAuthnRequest: true,
      signingKey: { privateKeyPem: "-----BEGIN PRIVATE KEY-----\n…" },
    }
    const r = await validate(bad)
    expect("issues" in r && (r.issues?.length ?? 0) > 0).toBe(true)
  })

  test("accepts an idpInitiated binding", async () => {
    const ok = {
      ...VALID,
      idpInitiated: {
        defaultClientId: "rp-1",
        defaultRedirectUri: "https://app.example/landing",
      },
    }
    const r = await validate(ok)
    expect("issues" in r && r.issues).toBeFalsy()
  })

  test("rejects an unknown nameIdFormat", async () => {
    const bad = {
      ...VALID,
      idp: { ...VALID.idp, nameIdFormat: "kerberos" },
    }
    const r = await validate(bad)
    expect("issues" in r && (r.issues?.length ?? 0) > 0).toBe(true)
  })
})
