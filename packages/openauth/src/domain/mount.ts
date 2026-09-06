/**
 * Mount prefix — where this IdP sits under its origin.
 *
 * The library serves its routes at its own root (`/authorize`, `/m/*`,
 * `/cb/*`); a deployment may sit behind a reverse proxy that strips a path
 * prefix before forwarding. Routing is unaffected — but every URL the
 * library *emits* (form actions, upstream `redirect_uri`s, SAML metadata)
 * is consumed on the public side of that proxy and must carry the prefix.
 *
 * `issuerUrl` already carries it. It is the single source of truth: there
 * is deliberately no `basePath` option, because two sources could disagree
 * and the `iss` claim would then contradict the URLs we hand out.
 *
 * All emitted-URL construction goes through this module. `metadata.test.ts`
 * is an anti-drift test asserting the SAML entityID/ACS equal what
 * `buildAuthnRequestRedirect` derives; funnelling every site through
 * `callbackTarget` is what keeps that true.
 */

/**
 * The normalised mount prefix of `issuerUrl`: `""` for a root-mounted
 * deployment, otherwise a leading-slash, no-trailing-slash path.
 *
 *     https://example.com        -> ""
 *     https://example.com/       -> ""
 *     https://example.com/idp    -> "/idp"
 *     https://example.com/idp/   -> "/idp"
 *     https://example.com//idp// -> "/idp"
 *
 * A root-mounted issuer must yield `""` and not `"/"`, so that existing
 * deployments emit byte-identical URLs to before this existed.
 *
 * An unparseable `issuerUrl` yields `""` rather than throwing: emitting a
 * root-relative URL degrades to the pre-existing behaviour, whereas
 * throwing would turn a misconfiguration into a 500 from inside form
 * rendering. Misconfiguration still fails loudly at `/authorize`, which
 * parses `issuerUrl` for the callback host.
 */
export function mountPath(issuerUrl: string): string {
  let pathname: string
  try {
    pathname = new URL(issuerUrl).pathname
  } catch {
    return ""
  }
  const segments = pathname.split("/").filter(Boolean)
  return segments.length === 0 ? "" : `/${segments.join("/")}`
}

/**
 * A path-absolute URL for one of the library's own routes, carrying the
 * deployment's mount prefix. `path` is the route as the service itself
 * serves it, with a leading slash.
 *
 *     mountedPath("https://x/idp", "/m/code/send") -> "/idp/m/code/send"
 *     mountedPath("https://x",     "/m/code/send") -> "/m/code/send"
 */
export function mountedPath(issuerUrl: string, path: string): string {
  return `${mountPath(issuerUrl)}${path}`
}

/**
 * Where a method's callback lives, in the two forms the framework needs.
 *
 * The distinction matters under a path-mounted deployment and is the
 * reason these are derived together rather than one from the other:
 * `url` is public (registered with upstream providers, advertised in SAML
 * metadata) and carries the mount prefix, while `path` is what the
 * inbound request actually looks like after the proxy has stripped that
 * prefix, and so must not.
 */
export type CallbackTarget = {
  /** Public, fully-qualified callback URL. Carries the mount prefix. */
  url: string
  /** Host the callback is expected to arrive on. */
  host: string
  /**
   * Expected pathname of the inbound request — this service's own route,
   * *without* the mount prefix, because the proxy has already stripped it.
   * Persisted on `FlowRecord.callbackPath` and matched in `domain/callback.ts`.
   */
  path: string
}

/**
 * The single derivation point for a method's callback URL.
 *
 * `callbackHost` is the optional per-tenant override from
 * `IdPOptions.callbackHostFor`. **The issuer's mount prefix applies even
 * when that override is in effect.** `callbackHostFor` exists to partition
 * callbacks across hostnames so a tenant is recoverable from the `Host`
 * header before the state envelope is verified (tenant-recovery mechanism
 * #2) — it varies the authority of the *same* deployment, not the
 * deployment itself. Those hosts are served by this service behind the
 * same proxy, so they share its mount. A deployment needing partitioned
 * hosts mounted differently from the issuer is describing two mounts,
 * which one `issuerUrl` cannot express and a second option must not be
 * introduced to paper over.
 */
export function callbackTarget(input: {
  issuerUrl: string
  methodId: string
  callbackHost?: string | undefined
}): CallbackTarget {
  const issuer = new URL(input.issuerUrl)
  const host = input.callbackHost ?? issuer.host
  const path = `/cb/${input.methodId}`
  return {
    host,
    path,
    url: `${issuer.protocol}//${host}${mountPath(input.issuerUrl)}${path}`,
  }
}
