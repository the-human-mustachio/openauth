/**
 * Mount prefix derivation and the emitted-URL contract.
 *
 * The regression bar for this feature is that a **root-mounted** issuer
 * emits byte-identical URLs to what it emitted before mount support
 * existed — most deployments are root-mounted and their registered
 * `redirect_uri`s must keep working untouched. Every case below that
 * asserts a bare `/m/...` or `https://host/cb/...` is guarding that.
 */
import { describe, expect, test } from "bun:test"

import { callbackTarget, mountPath, mountedPath } from "../../src/domain/mount"

describe("mountPath", () => {
  test('root-mounted issuers yield the empty string, never "/"', () => {
    // "/" would produce "//m/code/send" — a protocol-relative URL that
    // the browser resolves against a *different origin*.
    expect(mountPath("https://example.com")).toBe("")
    expect(mountPath("https://example.com/")).toBe("")
    expect(mountPath("https://example.com//")).toBe("")
  })

  test("a path-mounted issuer yields a normalised prefix", () => {
    expect(mountPath("https://example.com/idp")).toBe("/idp")
    expect(mountPath("https://example.com/idp/")).toBe("/idp")
    expect(mountPath("https://example.com//idp//")).toBe("/idp")
    expect(mountPath("https://example.com/a/b/c")).toBe("/a/b/c")
    expect(mountPath("https://example.com/a//b/")).toBe("/a/b")
  })

  test("query and fragment on the issuer are not part of the mount", () => {
    expect(mountPath("https://example.com/idp?x=1")).toBe("/idp")
    expect(mountPath("https://example.com/idp#frag")).toBe("/idp")
  })

  test("port and scheme do not affect the prefix", () => {
    expect(mountPath("http://localhost:3000/idp")).toBe("/idp")
    expect(mountPath("http://localhost:3000")).toBe("")
  })

  test("an unparseable issuer degrades to root rather than throwing", () => {
    // Form rendering calls this; a throw here would turn a config typo
    // into a 500 from inside a login page. `/authorize` still fails
    // loudly, because it parses `issuerUrl` for the callback host.
    expect(mountPath("not a url")).toBe("")
    expect(mountPath("")).toBe("")
  })
})

describe("mountedPath", () => {
  test("root-mounted output is unchanged from a bare literal", () => {
    expect(mountedPath("https://example.com", "/m/code/send")).toBe(
      "/m/code/send",
    )
    expect(mountedPath("https://example.com/", "/m/pw/login")).toBe(
      "/m/pw/login",
    )
  })

  test("path-mounted output carries the prefix", () => {
    expect(mountedPath("https://example.com/idp", "/m/code/send")).toBe(
      "/idp/m/code/send",
    )
    expect(mountedPath("https://example.com/idp/", "/m/code/verify")).toBe(
      "/idp/m/code/verify",
    )
    expect(
      mountedPath("https://example.com/auth/idp", "/m/pk/authenticate-options"),
    ).toBe("/auth/idp/m/pk/authenticate-options")
  })
})

describe("callbackTarget", () => {
  test("root-mounted: url is byte-identical to the pre-mount construction", () => {
    const t = callbackTarget({
      issuerUrl: "https://example.com",
      methodId: "oidc",
    })
    expect(t.url).toBe("https://example.com/cb/oidc")
    expect(t.host).toBe("example.com")
    expect(t.path).toBe("/cb/oidc")
  })

  test("path-mounted: url carries the prefix, path does not", () => {
    const t = callbackTarget({
      issuerUrl: "https://example.com/idp",
      methodId: "oidc",
    })
    // Registered with the upstream provider — must be reachable publicly.
    expect(t.url).toBe("https://example.com/idp/cb/oidc")
    // Matched against the inbound request, which the proxy has already
    // stripped. Prefixing this would reject every callback.
    expect(t.path).toBe("/cb/oidc")
  })

  test("the issuer's port is preserved", () => {
    expect(
      callbackTarget({
        issuerUrl: "http://localhost:3000/idp",
        methodId: "g",
      }).url,
    ).toBe("http://localhost:3000/idp/cb/g")
  })

  test("callbackHostFor overrides the authority but inherits the mount", () => {
    // Documented decision: `callbackHostFor` partitions callbacks across
    // hostnames for tenant recovery — it varies the authority of the same
    // deployment, so those hosts share its mount.
    const t = callbackTarget({
      issuerUrl: "https://example.com/idp",
      methodId: "oidc",
      callbackHost: "acme.example.com",
    })
    expect(t.url).toBe("https://acme.example.com/idp/cb/oidc")
    expect(t.host).toBe("acme.example.com")
    expect(t.path).toBe("/cb/oidc")
  })

  test("callbackHostFor on a root-mounted issuer is unchanged", () => {
    const t = callbackTarget({
      issuerUrl: "https://example.com",
      methodId: "oidc",
      callbackHost: "acme.example.com",
    })
    expect(t.url).toBe("https://acme.example.com/cb/oidc")
  })

  test("an explicitly undefined callbackHost falls back to the issuer's", () => {
    // `deps.callbackHostFor?.(id)` yields undefined when unconfigured.
    const t = callbackTarget({
      issuerUrl: "https://example.com/idp",
      methodId: "oidc",
      callbackHost: undefined,
    })
    expect(t.url).toBe("https://example.com/idp/cb/oidc")
  })
})
