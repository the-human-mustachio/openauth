---
"@_mustachio/openauth": patch
---

Fix SAML Single Logout over the HTTP-Redirect binding, which failed signature verification on newer runtimes.

The redirect binding signs the raw query octets (OASIS SAML 2.0 Bindings §3.4.4.1), so verification must see the exact bytes the IdP signed. The `/sls` handler was obtaining them via `new URL(request.url).search`, which round-trips the query through whatever URL encoder the runtime ships. Whether that round-trip preserves bytes turns out to be a property of the runtime rather than of the request: it holds on Bun 1.1 and does not on Bun 1.4, where every inbound redirect-binding `LogoutRequest` was rejected with a signature failure. The HTTP-POST binding was unaffected, since it never touches the query string.

The query is now sliced directly out of the request URL, with no encoder in the path.

If you deploy SAML SLO on Bun 1.2 or later, inbound IdP-initiated logout over the redirect binding was broken before this release.
