/**
 * Helpers that prepare a `Request` for the host-supplied
 * `IdPOptions.resolveTenant` hook.
 *
 * The canonical resolver reads `client_id` from URL search params
 * (INTEGRATION.md §5.1). On endpoints where `client_id` is carried in
 * the form body / Basic-auth header rather than the URL (m2m at
 * `/token`, introspect at `/introspect`, revoke at `/revoke`) the
 * framework parses the body first and then injects the parsed
 * `client_id` into a synthesized request so the resolver still sees
 * what it expects.
 */

/**
 * Build a new `Request` whose URL search params carry the supplied
 * resolver hints. Existing query params win — hosts can still override
 * via the URL. Headers are copied so Basic-auth-based resolvers still
 * see the original `Authorization`. The body is intentionally dropped:
 * the original is already consumed by the handler and resolvers must
 * not depend on body state.
 */
export function injectResolverHints(
  original: Request,
  hints: Record<string, string>,
): Request {
  const url = new URL(original.url)
  for (const [k, v] of Object.entries(hints)) {
    if (!url.searchParams.has(k)) url.searchParams.set(k, v)
  }
  return new Request(url.toString(), {
    method: original.method,
    headers: original.headers,
  })
}
