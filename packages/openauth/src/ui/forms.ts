/**
 * Server-rendered HTML helpers for the bundled credential methods and the
 * default authorization picker.
 *
 * Intentionally minimal — zero JS, no client framework. Hosts that want a
 * richer UI override `IdPOptions.renderPicker` (for method selection) or
 * supply their own `success-response` from method handlers (for credential
 * forms). The helpers escape user-provided strings so callers can drop
 * arbitrary labels or error messages without thinking about XSS.
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

export const BASE_STYLES = `
:root {
  color-scheme: light dark;

  --bg-page: #eef0f4;
  --bg-card: #ffffff;
  --bg-input: #ffffff;
  --bg-row: #f5f6f8;
  --bg-row-hover: #eaecf1;
  --fg-high: #0e1116;
  --fg-mid: #4a5160;
  --fg-low: #8b93a3;
  --border: #d8dce3;
  --border-strong: #9aa3b2;
  --primary: #2f3137;
  --primary-fg: #ffffff;
  --primary-hover: #1b1d22;
  --focus-ring: rgba(47, 49, 55, 0.18);
  --error-bg: #fdecec;
  --error-fg: #8a1a1a;
  --radius: 8px;
  --shadow-card: 0 1px 2px rgba(15, 18, 25, 0.04), 0 12px 28px rgba(15, 18, 25, 0.08);
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg-page: #0e0f12;
    --bg-card: #16181d;
    --bg-input: #1c1f25;
    --bg-row: #20242c;
    --bg-row-hover: #2a2f38;
    --fg-high: #f3f4f6;
    --fg-mid: #b6bcc7;
    --fg-low: #7a8190;
    --border: #2a2e36;
    --border-strong: #3a4049;
    --primary: #f3f4f6;
    --primary-fg: #0e1116;
    --primary-hover: #ffffff;
    --focus-ring: rgba(243, 244, 246, 0.22);
    --error-bg: #2a1414;
    --error-fg: #f5b4b4;
    --shadow-card: 0 1px 2px rgba(0, 0, 0, 0.5), 0 18px 40px rgba(0, 0, 0, 0.5);
  }
}

* { box-sizing: border-box; }

html, body { margin: 0; padding: 0; }

body {
  min-height: 100vh;
  background: var(--bg-page);
  color: var(--fg-high);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", "Inter", "Helvetica Neue", sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  font-size: 15px;
  line-height: 1.45;
  display: grid;
  place-items: center;
  padding: 1.5rem;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

main {
  max-width: 380px;
  width: 100%;
  padding: 2rem 1.75rem;
  background: var(--bg-card);
  border-radius: var(--radius);
  box-shadow: var(--shadow-card);
}

h1 {
  font-size: 1.125rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  margin: 0 0 1.25rem;
  color: var(--fg-high);
}

form {
  display: grid;
  gap: 0.85rem;
  margin: 0;
}

label {
  display: grid;
  gap: 0.4rem;
  font-size: 0.78rem;
  font-weight: 500;
  color: var(--fg-mid);
  text-transform: none;
}

input {
  width: 100%;
  height: 2.5rem;
  padding: 0 0.85rem;
  background: var(--bg-input);
  color: var(--fg-high);
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) - 2px);
  font-size: 0.95rem;
  font-family: inherit;
  outline: none;
  transition: border-color 120ms ease, box-shadow 120ms ease;
}
input::placeholder { color: var(--fg-low); }
input:hover { border-color: var(--border-strong); }
input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--focus-ring);
}
input:user-invalid:not(:focus) {
  border-color: var(--error-fg);
}

button {
  height: 2.5rem;
  padding: 0 1rem;
  border: 0;
  border-radius: calc(var(--radius) - 2px);
  background: var(--primary);
  color: var(--primary-fg);
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  transition: background 120ms ease, transform 80ms ease;
}
button:hover { background: var(--primary-hover); }
button:active { transform: translateY(1px); }
button:focus-visible { box-shadow: 0 0 0 3px var(--focus-ring); outline: none; }

.error {
  display: flex;
  align-items: center;
  min-height: 2.25rem;
  padding: 0.5rem 0.85rem;
  margin: 0 0 0.25rem;
  background: var(--error-bg);
  color: var(--error-fg);
  font-size: 0.82rem;
  border-radius: calc(var(--radius) - 2px);
}

.methods {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 0.5rem;
}
.methods a {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 2.75rem;
  padding: 0 1rem;
  background: var(--bg-row);
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) - 2px);
  color: var(--fg-high);
  font-size: 0.92rem;
  font-weight: 500;
  text-decoration: none;
  transition: background 120ms ease, border-color 120ms ease, transform 80ms ease;
}
.methods a::after {
  content: "›";
  color: var(--fg-mid);
  font-size: 1.15rem;
  font-weight: 500;
  line-height: 1;
}
.methods a:hover {
  background: var(--bg-row-hover);
  border-color: var(--border-strong);
  color: var(--fg-high);
}
.methods a:hover::after {
  color: var(--fg-high);
}
.methods a:active { transform: translateY(1px); }
.methods a:focus-visible {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--focus-ring);
}
`

export function htmlPage(opts: { title: string; body: string }): string {
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
