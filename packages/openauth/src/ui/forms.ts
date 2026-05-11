/**
 * Server-rendered HTML helpers for the bundled credential methods.
 *
 * Intentionally minimal — Phase 4 ships forms that work everywhere with
 * zero JavaScript. Theming + richer customization arrive in later phases.
 * Helpers escape user-provided strings so methods can drop arbitrary error
 * messages or labels in without thinking about XSS.
 */

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&":
        return "&amp;"
      case "<":
        return "&lt;"
      case ">":
        return "&gt;"
      case '"':
        return "&quot;"
      case "'":
        return "&#39;"
      default:
        return c
    }
  })
}

export function htmlPage(opts: {
  title: string
  body: string
  styleId?: string
}): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(opts.title)}</title>
  <style>${BASE_STYLES}</style>
</head>
<body>
  <main>${opts.body}</main>
</body>
</html>`
}

const BASE_STYLES = `
:root {
  color-scheme: light dark;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
}
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; }
@media (prefers-color-scheme: dark) { body { background: #15161a; } }
main { max-width: 360px; width: 100%; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 4px 18px rgba(0,0,0,0.08); }
@media (prefers-color-scheme: dark) { main { background: #1f2128; box-shadow: 0 4px 18px rgba(0,0,0,0.4); } }
h1 { font-size: 1.25rem; margin: 0 0 1rem; }
form { display: grid; gap: 0.75rem; }
label { display: grid; gap: 0.25rem; font-size: 0.875rem; }
input { padding: 0.5rem 0.75rem; border: 1px solid #d0d5dd; border-radius: 6px; font-size: 1rem; background: inherit; color: inherit; }
button { padding: 0.55rem; border: 0; border-radius: 6px; background: #2563eb; color: white; font-size: 1rem; cursor: pointer; }
button:hover { background: #1d4ed8; }
.error { color: #b42318; font-size: 0.875rem; margin: 0 0 0.5rem; }
`

export type FormField = {
  name: string
  label: string
  type?: "text" | "password" | "email" | "tel"
  value?: string
  required?: boolean
  autocomplete?: string
  inputmode?: string
}

/** Build a `<form>` POSTing to `action`. */
export function renderForm(opts: {
  title: string
  action: string
  fields: FormField[]
  submit: string
  error?: string
  hidden?: Record<string, string>
}): string {
  const errorHtml = opts.error
    ? `<p class="error">${escapeHtml(opts.error)}</p>`
    : ""
  const hidden = Object.entries(opts.hidden ?? {})
    .map(
      ([k, v]) =>
        `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`,
    )
    .join("")
  const fields = opts.fields
    .map(
      (f) => `<label>${escapeHtml(f.label)}
<input
  name="${escapeHtml(f.name)}"
  type="${f.type ?? "text"}"
  value="${escapeHtml(f.value ?? "")}"
  ${f.required ? "required" : ""}
  ${f.autocomplete ? `autocomplete="${escapeHtml(f.autocomplete)}"` : ""}
  ${f.inputmode ? `inputmode="${escapeHtml(f.inputmode)}"` : ""}
></label>`,
    )
    .join("")
  return htmlPage({
    title: opts.title,
    body: `<h1>${escapeHtml(opts.title)}</h1>${errorHtml}<form method="POST" action="${escapeHtml(opts.action)}">${hidden}${fields}<button type="submit">${escapeHtml(opts.submit)}</button></form>`,
  })
}
