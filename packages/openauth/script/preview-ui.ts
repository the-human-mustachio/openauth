/**
 * Local visual preview of the bundled forms + picker.
 *
 * Run: `bun run script/preview-ui.ts`
 *
 * Opens an index at http://localhost:4321/ with links to every sample
 * scenario. Useful for eyeballing `BASE_STYLES` changes in `src/ui/forms.ts`
 * without booting a full IdP. The page hot-reloads on file save via Bun's
 * watcher when launched with `bun --hot`.
 */
import { renderForm } from "../src/ui/forms"
import { renderPicker, type PickerContext } from "../src/ui/picker"

const PORT = Number(process.env.PORT ?? 4321)

const pickerCtx: PickerContext = {
  clientId: "demo-client",
  redirectUri: "https://app.example.com/callback",
  state: "demo-state",
  scope: "openid profile email",
  nonce: null,
  codeChallenge: null,
  codeChallengeMethod: null,
  audience: null,
  prompt: null,
  uiLocales: null,
}

const scenarios = {
  "picker-many": () =>
    renderPicker(
      [
        {
          id: "google-workspace",
          kind: "google",
          type: "redirect",
          displayName: "Continue with Google",
        },
        {
          id: "github",
          kind: "github",
          type: "redirect",
          displayName: "Continue with GitHub",
        },
        {
          id: "microsoft",
          kind: "microsoft",
          type: "redirect",
          displayName: "Continue with Microsoft",
        },
        {
          id: "password",
          kind: "password",
          type: "credential",
          displayName: "Sign in with email",
        },
        {
          id: "passkey",
          kind: "passkey",
          type: "credential",
          displayName: "Use a passkey",
        },
      ],
      pickerCtx,
    ),
  "picker-few": () =>
    renderPicker(
      [
        { id: "google", kind: "google", type: "redirect" },
        { id: "password", kind: "password", type: "credential" },
      ],
      pickerCtx,
    ),
  "form-login": () =>
    new Response(
      renderForm({
        title: "Sign in",
        action: "/m/password/login",
        submit: "Continue",
        fields: [
          {
            name: "email",
            label: "Email",
            type: "email",
            required: true,
            autocomplete: "email",
          },
          {
            name: "password",
            label: "Password",
            type: "password",
            required: true,
            autocomplete: "current-password",
          },
        ],
        hidden: { flow: "demo-flow-id" },
      }),
      htmlHeaders(),
    ),
  "form-login-error": () =>
    new Response(
      renderForm({
        title: "Sign in",
        action: "/m/password/login",
        submit: "Continue",
        error: "Incorrect email or password.",
        fields: [
          {
            name: "email",
            label: "Email",
            type: "email",
            required: true,
            value: "matt@sparkcx.co",
          },
          {
            name: "password",
            label: "Password",
            type: "password",
            required: true,
          },
        ],
      }),
      htmlHeaders(),
    ),
  "form-code": () =>
    new Response(
      renderForm({
        title: "Enter the code",
        action: "/m/code/verify",
        submit: "Verify",
        fields: [
          {
            name: "code",
            label: "We sent a 6-digit code to your email",
            type: "text",
            required: true,
            inputmode: "numeric",
            autocomplete: "one-time-code",
          },
        ],
      }),
      htmlHeaders(),
    ),
  "form-register": () =>
    new Response(
      renderForm({
        title: "Create your account",
        action: "/m/password/register",
        submit: "Create account",
        fields: [
          {
            name: "email",
            label: "Email",
            type: "email",
            required: true,
            autocomplete: "email",
          },
          {
            name: "password",
            label: "Password",
            type: "password",
            required: true,
            autocomplete: "new-password",
          },
          {
            name: "confirm",
            label: "Confirm password",
            type: "password",
            required: true,
          },
        ],
      }),
      htmlHeaders(),
    ),
} as const

type Scenario = keyof typeof scenarios

function htmlHeaders(): ResponseInit {
  return {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  }
}

function indexPage(): Response {
  const links = (Object.keys(scenarios) as Scenario[])
    .map((id) => `<li><a href="/${id}">${id}</a></li>`)
    .join("")
  const body = `<!doctype html><html><head>
<meta charset="utf-8">
<title>UI preview</title>
<style>
  :root { color-scheme: light dark; --fg: #14171f; --link: #1d4ed8; --link-hover: #1e3a8a; --card-bg: #ffffff; --card-border: #d8dce3; --muted: #6b7280; --code-bg: rgba(0,0,0,0.06); }
  @media (prefers-color-scheme: dark) {
    :root { --fg: #f3f4f6; --link: #93c5fd; --link-hover: #ffffff; --card-bg: #16181d; --card-border: #2a2e36; --muted: #b6bcc7; --code-bg: rgba(255,255,255,0.08); background: #0e0f12; }
  }
  body { font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; max-width: 36rem; margin: 3rem auto; padding: 0 1.25rem; color: var(--fg); }
  h1 { font-size: 1.2rem; margin: 0 0 0.5rem; }
  p { color: var(--muted); margin: 0 0 1.5rem; }
  ul { padding: 0; list-style: none; display: grid; gap: 0.4rem; }
  li a {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0.65rem 0.9rem;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 6px;
    color: var(--link);
    text-decoration: none;
    font-weight: 500;
  }
  li a::after { content: "→"; color: var(--muted); }
  li a:hover { color: var(--link-hover); border-color: var(--link); }
  li a:hover::after { color: var(--link-hover); }
  code { background: var(--code-bg); padding: 1px 5px; border-radius: 4px; font-size: 0.85em; }
</style>
</head><body>
<h1>OpenAuth UI preview</h1>
<p>Tweak <code>src/ui/forms.ts</code> &rarr; refresh.</p>
<ul>${links}</ul>
</body></html>`
  return new Response(body, htmlHeaders())
}

const server = Bun.serve({
  port: PORT,
  fetch(req) {
    const path = new URL(req.url).pathname.slice(1)
    if (path === "" || path === "index") return indexPage()
    if (path in scenarios) {
      const out = scenarios[path as Scenario]()
      return out instanceof Response ? out : out
    }
    return new Response("not found", { status: 404 })
  },
})

console.log(`UI preview → http://localhost:${server.port}/`)
