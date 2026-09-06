/**
 * `codeMethod` — magic-code (email / SMS) credential factory.
 *
 * Routes:
 *   GET  /authorize → render destination form (email or phone input).
 *   POST /send      → mint code, call `sendCode(destination, code)` hook,
 *                      stash hashed code in `methodState`, render verify form.
 *   POST /verify    → compare submitted code against stored hash; on match,
 *                      return `success` with the destination as provider
 *                      subject.
 *
 * The framework's flow record TTL (10 minutes) doubles as the code TTL —
 * the methodState rolls off when the flow does.
 *
 * Anti-enumeration: the `/send` route always renders the verify form,
 * whether or not the destination is valid. The user-supplied `sendCode`
 * hook can silently no-op for unknown destinations.
 */
import { z } from "zod"

import {
  base64url,
  randomBytes,
  sha256,
  timingSafeEqualStr,
  utf8,
} from "../domain/crypto"
import type {
  AuthMethod,
  AuthMethodFactory,
  MethodContext,
  MethodResult,
} from "../types/method"
import { mountedPath } from "../domain/mount"
import { renderForm } from "../ui/forms"

export type CodeProperties = {
  destination: string
}

export type CodeState = {
  destination: string
  /** Base64url SHA-256 hash of the code; the plain code never persists. */
  codeHash: string
  /** Failed-verify counter. After 5 attempts the flow is denied. */
  attempts: number
  error?: string
}

export type CodeMethodOptions = {
  /**
   * Called when the user submits a destination. The hook receives the
   * generated code and is responsible for delivering it (email, SMS,
   * etc.). Returning normally means "delivery attempted"; the framework
   * does not inspect the outcome.
   */
  sendCode: (input: {
    destination: string
    code: string
    tenantId: string
  }) => Promise<void>
  /**
   * Override code generation. Default: 6-digit numeric.
   *
   * Kept on the factory closure (not per-tenant) because the generation
   * algorithm is part of the host's overall deliverability + UX
   * decisions, not something that should be reconfigured per tenant.
   */
  generateCode?: () => string
}

/**
 * Per-tenant config. Host supplies these via `MethodConfig.config` so
 * each tenant can ship its own code length, attempt cap, channel kind,
 * and copy without instantiating a new factory.
 */
const configSchema = z.object({
  /** Default 6. Range 4–10. */
  codeLength: z.number().int().min(4).max(10).optional(),
  /** Default 5. After this many failed verifies the flow is denied. */
  maxAttempts: z.number().int().min(1).max(20).optional(),
  /** Default "email". */
  destinationKind: z.enum(["email", "tel", "any"]).optional(),
  /** Form copy overrides. */
  titles: z
    .object({
      request: z.string().optional(),
      verify: z.string().optional(),
    })
    .optional(),
})
type CodeConfig = z.infer<typeof configSchema>

const sendBody = z.object({
  destination: z.string().min(1),
})
const verifyBody = z.object({
  code: z.string().min(1),
})

export function codeMethod(
  opts: CodeMethodOptions,
): AuthMethodFactory<CodeProperties, CodeState, CodeConfig> {
  const customGenerator = opts.generateCode
  return {
    kind: "code",
    configSchema,
    build: async ({
      id,
      kind,
      config,
    }): Promise<AuthMethod<CodeProperties, CodeState>> => {
      const titleRequest = config.titles?.request ?? "Sign in"
      const titleVerify = config.titles?.verify ?? "Enter your code"
      const maxAttempts = config.maxAttempts ?? 5
      const destinationKind = config.destinationKind ?? "email"
      const codeLength = config.codeLength ?? 6
      const generateCode = customGenerator ?? (() => defaultCode(codeLength))
      return {
        id,
        kind,
        type: "code",
        routes: {
          "GET /authorize": async (ctx) => ({
            kind: "challenge",
            response: htmlResponse(
              renderForm({
                title: titleRequest,
                action: mountedPath(ctx.issuerUrl, `/m/${id}/send`),
                fields: destinationField(destinationKind),
                submit: "Send code",
              }),
            ),
          }),
          "POST /send": async (ctx) =>
            handleSend(
              ctx,
              id,
              titleRequest,
              titleVerify,
              destinationKind,
              generateCode,
              opts.sendCode,
            ),
          "POST /verify": async (ctx) =>
            handleVerify(ctx, id, titleVerify, maxAttempts),
        },
      }
    },
  }
}

async function handleSend(
  ctx: MethodContext<CodeState>,
  methodId: string,
  titleRequest: string,
  titleVerify: string,
  destinationKind: "email" | "tel" | "any",
  generateCode: () => string,
  sendCode: CodeMethodOptions["sendCode"],
): Promise<MethodResult<CodeProperties, CodeState>> {
  const form = await safeForm(ctx.request)
  const parsed = sendBody.safeParse(form)
  if (
    !parsed.success ||
    !validateDestination(parsed.data?.destination, destinationKind)
  ) {
    return {
      kind: "challenge",
      response: htmlResponse(
        renderForm({
          title: titleRequest,
          action: mountedPath(ctx.issuerUrl, `/m/${methodId}/send`),
          fields: destinationField(destinationKind),
          submit: "Send code",
          error: "Please enter a valid destination.",
        }),
        400,
      ),
    }
  }
  const destination = parsed.data.destination
  const code = generateCode()
  // Side effect best-effort: deliveries can fail but we still render the
  // verify form so we never leak whether the destination exists.
  try {
    await sendCode({ destination, code, tenantId: ctx.tenant.id })
  } catch {
    /* swallow — the user retries via the resend control. */
  }
  const hash = base64url.encode(await sha256(utf8.encode(code)))
  return {
    kind: "challenge",
    response: htmlResponse(
      renderForm({
        title: titleVerify,
        action: mountedPath(ctx.issuerUrl, `/m/${methodId}/verify`),
        fields: [
          {
            name: "code",
            label: "Code",
            required: true,
            inputmode: "numeric",
            autocomplete: "one-time-code",
          },
        ],
        submit: "Verify",
        hidden: { destination },
      }),
    ),
    saveMethodState: {
      destination,
      codeHash: hash,
      attempts: 0,
    },
  }
}

async function handleVerify(
  ctx: MethodContext<CodeState>,
  methodId: string,
  titleVerify: string,
  maxAttempts: number,
): Promise<MethodResult<CodeProperties, CodeState>> {
  if (!ctx.methodState) {
    return {
      kind: "error",
      error: {
        code: "invalid_request",
        description: "verify without prior /send",
      },
    }
  }
  const state = ctx.methodState
  if (state.attempts >= maxAttempts) {
    return { kind: "denied", reason: "too_many_attempts" }
  }

  const form = await safeForm(ctx.request)
  const parsed = verifyBody.safeParse(form)
  if (!parsed.success) {
    return verifyError(
      ctx.issuerUrl,
      methodId,
      state,
      titleVerify,
      "Please enter the code.",
    )
  }

  const submittedHash = base64url.encode(
    await sha256(utf8.encode(parsed.data.code)),
  )
  if (!timingSafeEqualStr(submittedHash, state.codeHash)) {
    return verifyError(
      ctx.issuerUrl,
      methodId,
      { ...state, attempts: state.attempts + 1 },
      titleVerify,
      "Incorrect code. Please try again.",
    )
  }

  return {
    kind: "success",
    providerSubject: state.destination,
    properties: { destination: state.destination },
  }
}

function verifyError(
  issuerUrl: string,
  methodId: string,
  next: CodeState,
  titleVerify: string,
  error: string,
): MethodResult<CodeProperties, CodeState> {
  return {
    kind: "challenge",
    response: htmlResponse(
      renderForm({
        title: titleVerify,
        action: mountedPath(issuerUrl, `/m/${methodId}/verify`),
        fields: [
          {
            name: "code",
            label: "Code",
            required: true,
            inputmode: "numeric",
            autocomplete: "one-time-code",
          },
        ],
        submit: "Verify",
        error,
      }),
      400,
    ),
    saveMethodState: { ...next, error },
  }
}

function destinationField(kind: "email" | "tel" | "any") {
  if (kind === "email") {
    return [
      {
        name: "destination",
        label: "Email",
        type: "email" as const,
        required: true,
        autocomplete: "email",
      },
    ]
  }
  if (kind === "tel") {
    return [
      {
        name: "destination",
        label: "Phone",
        type: "tel" as const,
        required: true,
        autocomplete: "tel",
      },
    ]
  }
  return [
    {
      name: "destination",
      label: "Destination",
      type: "text" as const,
      required: true,
    },
  ]
}

function validateDestination(
  destination: string | undefined,
  kind: "email" | "tel" | "any",
): destination is string {
  if (!destination) return false
  if (kind === "email") return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(destination)
  if (kind === "tel") return /^[+\d][\d\s\-()]{6,}$/.test(destination)
  return destination.length > 0
}

function defaultCode(length: number): string {
  // Modulo over a uniform 32-bit draw — small skew on the high end of the
  // range, fine for codes gated by rate limiting + max-attempts.
  const buf = randomBytes(4)
  const view = new DataView(buf.buffer, buf.byteOffset, 4)
  const max = 10 ** length
  const n = view.getUint32(0) % max
  return n.toString().padStart(length, "0")
}

async function safeForm(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? ""
  if (!ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return {}
  }
  return Object.fromEntries(new URLSearchParams(await req.text()).entries())
}

function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  })
}
