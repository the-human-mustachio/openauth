---
"@_mustachio/openauth": patch
---

Correct the 0.13.1 release note, and stop the SAML redirect-binding SLO tests failing on Bun.

**0.13.1 described this wrongly.** It claimed inbound redirect-binding Single Logout "failed signature verification on newer runtimes" because the signature input was re-encoded by the runtime's URL parser. That diagnosis was wrong. The real cause is unrelated to URL encoding, and the impact is narrower than that note implied.

`@node-saml/node-saml` resolves an inbound `SigAlg` URI by trimming it to its fragment (`…#rsa-sha256`) and exact-matching that against `crypto.getHashes()` — which requires the legacy OpenSSL alias `RSA-SHA256`. Node.js exposes it. **Bun removed the `RSA-*` aliases in 1.2** (1.1 had 7, 1.4 has none), so on Bun the lookup throws `…#rsa-sha256 is not supported` and every inbound redirect-binding `LogoutRequest` is rejected.

**SAML is Node-only by design** — the `methods/saml-sp` subpath carries a `node` export condition — so on the supported runtime this always worked, and 0.13.1 fixed nothing that was broken there. What was actually broken was the test suite, which runs under Bun.

The two affected cases are now gated on the alias being present, so they run in full on Node and skip with a stated reason on Bun, alongside an assertion that keeps the constraint visible rather than letting a silent skip hide it. `INTEGRATION.md` § 9.5 documents the runtime requirement.

The 0.13.1 change itself is kept: reading the signature input straight from the request URL rather than round-tripping it through `new URL().search` is what the binding specifies (OASIS SAML 2.0 Bindings §3.4.4.1), and it removes a dependence on runtime URL-encoding behaviour. It simply was not the cause of the failure it was released to fix.
