---
"@_mustachio/openauth": patch
---

Fix every URL the library emits when the IdP is mounted under a path prefix.

Deploy behind a reverse proxy at a path — `issuerUrl: "https://example.com/idp"`, proxy strips `/idp` before forwarding — and routing, discovery, `iss` and token signing are all correct, but nothing a user can actually click is. Login forms posted to `https://example.com/m/<method>/send` and 404'd, so no sign-in of any kind could complete. The `redirect_uri` sent to upstream providers was `https://example.com/cb/<method>`, so Okta/Google/Cognito returned the user to a 404. SAML SP metadata advertised an ACS and an SLS with the same defect.

The cause was two families of construction that both dropped `issuerUrl`'s pathname: form actions written as path-absolute literals, and callback URLs rebuilt from `protocol` + `host`, which is scheme and authority only. Both now derive from a single helper that prepends the mount prefix taken from `issuerUrl` — the one source of truth, so there is no `basePath` option for it to disagree with.

**Root-mounted deployments are unaffected.** A pathname of `/` yields an empty prefix, so emitted URLs are byte-identical to before; that is asserted directly rather than assumed, since every registered `redirect_uri` in the wild depends on it.

**If you run path-mounted with an external provider, this is a breaking change.** The `redirect_uri` registered at your provider must be updated to the prefixed form (`https://example.com/idp/cb/<method>`), and SAML IdPs must re-import SP metadata to pick up the corrected ACS and SLS. If you worked around this by also routing `/m/*` and `/cb/*` at your proxy alongside the mounted prefix, those extra routes can now be deleted.

`MethodContext` gains an `issuerUrl` field, present on every route. Methods that render their own URLs need it where `dispatch` is null — a form action re-rendered after a validation error, for instance — and should build those with the exported mount helper rather than a literal. Custom methods only read this; the field is additive unless you construct a `MethodContext` yourself, as test fixtures do.

`FlowRecord.callbackPath` deliberately stays un-prefixed. It is matched against the inbound request, which the proxy has already stripped, so prefixing it would reject every callback — trading a 404 for a 400 rather than fixing anything. The public URL is reassembled where it is needed.
