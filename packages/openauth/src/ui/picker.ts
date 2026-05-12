/**
 * Default provider picker — rendered when an `/authorize` request matches
 * more than one enabled method and no `method_id` was specified.
 *
 * Hosts that want a fully custom UI override `IdPOptions.renderPicker`.
 * Both the default and any override return a `Response`; the framework
 * applies caching headers afterward.
 */
import { escapeHtml, htmlPage } from "./forms"

/** Minimal shape of a method as seen by the picker. */
export type PickerMethod = {
  /** Tenant-local id (e.g. "google-workspace"). Goes into method_id. */
  id: string
  /** Factory kind (e.g. "google"). Identifies the provider family. */
  kind: string
  /** "redirect" for upstream OAuth/OIDC, "credential" for password/code/passkey. */
  type: string
  /** Optional human-readable label provided by tenant config. */
  displayName?: string
}

/** Query params propagated into each picker option's link. */
export type PickerContext = {
  clientId: string
  redirectUri: string
  state?: string | null
  scope?: string | null
  nonce?: string | null
  codeChallenge?: string | null
  codeChallengeMethod?: string | null
  audience?: string | null
  prompt?: string | null
  uiLocales?: string | null
}

/**
 * Build an `/authorize` URL that pre-selects a specific `method_id` while
 * carrying every other OAuth param through unchanged.
 */
export function buildMethodLink(
  methodId: string,
  ctx: PickerContext,
): string {
  const params = new URLSearchParams()
  params.set("client_id", ctx.clientId)
  params.set("redirect_uri", ctx.redirectUri)
  params.set("response_type", "code")
  params.set("method_id", methodId)
  if (ctx.state) params.set("state", ctx.state)
  if (ctx.scope) params.set("scope", ctx.scope)
  if (ctx.nonce) params.set("nonce", ctx.nonce)
  if (ctx.codeChallenge) params.set("code_challenge", ctx.codeChallenge)
  if (ctx.codeChallengeMethod)
    params.set("code_challenge_method", ctx.codeChallengeMethod)
  if (ctx.audience) params.set("audience", ctx.audience)
  if (ctx.prompt) params.set("prompt", ctx.prompt)
  if (ctx.uiLocales) params.set("ui_locales", ctx.uiLocales)
  return `?${params.toString()}`
}

/** Default styled HTML picker. */
export function renderPicker(
  methods: PickerMethod[],
  ctx: PickerContext,
): Response {
  const items = methods
    .map((m) => {
      const label = m.displayName ?? prettyKind(m.kind)
      return `<li><a href="${escapeHtml(buildMethodLink(m.id, ctx))}">${escapeHtml(label)}</a></li>`
    })
    .join("")
  const body = `<h1>Sign in</h1><ul class="methods">${items}</ul>`
  return new Response(htmlPage({ title: "Sign in", body }), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  })
}

function prettyKind(kind: string): string {
  if (!kind) return "Continue"
  return kind
    .split(/[-_]/)
    .map((p) => (p.length === 0 ? p : p[0]!.toUpperCase() + p.slice(1)))
    .join(" ")
}
