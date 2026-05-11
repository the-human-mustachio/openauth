/**
 * `passkeyMethod` — WebAuthn factory using `@simplewebauthn/server`.
 *
 * Routes:
 *   GET  /authorize                 → render the username form.
 *   POST /authenticate-options      → mint challenge, return PublicKeyCredentialRequestOptionsJSON.
 *   POST /authenticate-verify       → verify assertion, return success.
 *   POST /register-options          → mint registration challenge, return options.
 *   POST /register-verify           → verify attestation, persist credential.
 *
 * The framework knows nothing about credentials; the tenant supplies a
 * `credentials` store. The method calls into it for lookups + writes. The
 * RP id and origin are configured per factory at build time; multi-domain
 * tenants instantiate multiple factories with distinct ids.
 *
 * Phase 4 ships the authentication ceremony end-to-end and exposes the
 * registration helpers so the management console (Phase 7) can wire them
 * up. Full registration UI / passkey enrollment flow polishes lands with
 * the console.
 */
import { z } from "zod"
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"

import type {
  AuthMethod,
  AuthMethodFactory,
  MethodContext,
  MethodResult,
} from "../types/method"
import { renderForm } from "../ui/forms"

export type PasskeyProperties = {
  userId: string
  credentialId: string
}

export type StoredCredential = {
  /** Base64url credential id. */
  credentialId: string
  /** Base64url public key. */
  publicKey: string
  /** WebAuthn signature counter for replay protection. */
  counter: number
  /** Optional transports hint stored at registration. */
  transports?: string[]
  userId: string
}

export type PasskeyCredentialStore = {
  findByUsername(
    username: string,
    tenantId: string,
  ): Promise<{ userId: string; credentials: StoredCredential[] } | null>
  findById(
    credentialId: string,
    tenantId: string,
  ): Promise<StoredCredential | null>
  /** Update the signature counter after a successful verification. */
  updateCounter(input: {
    credentialId: string
    counter: number
    tenantId: string
  }): Promise<void>
  /** Persist a newly-registered credential. */
  create?(input: {
    userId: string
    credential: StoredCredential
    tenantId: string
  }): Promise<void>
}

export type PasskeyMethodOptions = {
  rpName: string
  /** RP id (the registrable domain). e.g. `"acme.example"`. */
  rpID: string
  /** Expected origin(s). e.g. `["https://acme.example"]`. */
  origin: string | string[]
  credentials: PasskeyCredentialStore
  title?: string
}

export type PasskeyState =
  | { phase: "auth"; challenge: string; username: string }
  | { phase: "register"; challenge: string; userId: string; username: string }

const configSchema = z.object({}).strict()
type PasskeyConfig = z.infer<typeof configSchema>

const usernameBody = z.object({ username: z.string().min(1) })
const verifyBody = z.object({ response: z.string().min(1) })

export function passkeyMethod(
  opts: PasskeyMethodOptions,
): AuthMethodFactory<PasskeyProperties, PasskeyState, PasskeyConfig> {
  const title = opts.title ?? "Sign in with passkey"

  return {
    kind: "passkey",
    configSchema,
    build: async ({
      id,
      kind,
    }): Promise<AuthMethod<PasskeyProperties, PasskeyState>> => ({
      id,
      kind,
      type: "passkey",
      routes: {
        "GET /authorize": async () => ({
          kind: "challenge",
          response: htmlResponse(
            renderForm({
              title,
              action: `/m/${id}/authenticate-options`,
              fields: [
                {
                  name: "username",
                  label: "Username",
                  required: true,
                  autocomplete: "username webauthn",
                },
              ],
              submit: "Continue",
            }),
          ),
        }),
        "POST /authenticate-options": async (ctx) =>
          authOptions(ctx, opts),
        "POST /authenticate-verify": async (ctx) =>
          authVerify(ctx, opts),
        "POST /register-options": async (ctx) =>
          registerOptions(ctx, id, opts),
        "POST /register-verify": async (ctx) =>
          registerVerify(ctx, opts),
      },
    }),
  }
}

async function authOptions(
  ctx: MethodContext<PasskeyState>,
  opts: PasskeyMethodOptions,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  const form = await safeForm(ctx.request)
  const parsed = usernameBody.safeParse(form)
  if (!parsed.success) {
    return errorResult("missing username")
  }
  const found = await opts.credentials.findByUsername(
    parsed.data.username,
    ctx.tenant.id,
  )
  if (!found) {
    return errorResult("unknown user")
  }
  const options = await generateAuthenticationOptions({
    rpID: opts.rpID,
    allowCredentials: found.credentials.map((c) => ({
      id: c.credentialId,
      ...(c.transports ? { transports: c.transports as never } : {}),
    })),
    userVerification: "preferred",
  })
  return {
    kind: "challenge",
    response: jsonResponse(options),
    saveMethodState: {
      phase: "auth",
      challenge: options.challenge,
      username: parsed.data.username,
    },
  }
}

async function authVerify(
  ctx: MethodContext<PasskeyState>,
  opts: PasskeyMethodOptions,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  if (!ctx.methodState || ctx.methodState.phase !== "auth") {
    return errorResult("verify without prior /authenticate-options")
  }
  const state = ctx.methodState
  const form = await safeForm(ctx.request)
  const parsed = verifyBody.safeParse(form)
  if (!parsed.success) return errorResult("missing response")

  let assertion
  try {
    assertion = JSON.parse(parsed.data.response)
  } catch {
    return errorResult("malformed WebAuthn response")
  }
  const credentialId = assertion?.id as string | undefined
  if (!credentialId) return errorResult("missing credential id")
  const stored = await opts.credentials.findById(credentialId, ctx.tenant.id)
  if (!stored) return errorResult("unknown credential")

  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: state.challenge,
      expectedOrigin: opts.origin,
      expectedRPID: opts.rpID,
      credential: {
        id: stored.credentialId,
        publicKey: base64urlDecode(stored.publicKey),
        counter: stored.counter,
        ...(stored.transports
          ? { transports: stored.transports as never }
          : {}),
      },
    })
  } catch (e) {
    return errorResult(
      e instanceof Error ? e.message : "verification threw",
    )
  }
  if (!verification.verified) {
    return errorResult("verification rejected")
  }
  await opts.credentials.updateCounter({
    credentialId: stored.credentialId,
    counter: verification.authenticationInfo.newCounter,
    tenantId: ctx.tenant.id,
  })

  return {
    kind: "success",
    providerSubject: stored.userId,
    properties: { userId: stored.userId, credentialId: stored.credentialId },
  }
}

async function registerOptions(
  ctx: MethodContext<PasskeyState>,
  _methodId: string,
  opts: PasskeyMethodOptions,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  if (!opts.credentials.create) {
    return errorResult("registration not enabled")
  }
  const form = await safeForm(ctx.request)
  const parsed = usernameBody.safeParse(form)
  if (!parsed.success) return errorResult("missing username")

  const userId = parsed.data.username
  const options = await generateRegistrationOptions({
    rpName: opts.rpName,
    rpID: opts.rpID,
    userName: parsed.data.username,
    userID: new TextEncoder().encode(userId),
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  })
  return {
    kind: "challenge",
    response: jsonResponse(options),
    saveMethodState: {
      phase: "register",
      challenge: options.challenge,
      userId,
      username: parsed.data.username,
    },
  }
}

async function registerVerify(
  ctx: MethodContext<PasskeyState>,
  opts: PasskeyMethodOptions,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  if (!opts.credentials.create) {
    return errorResult("registration not enabled")
  }
  if (!ctx.methodState || ctx.methodState.phase !== "register") {
    return errorResult("verify without prior /register-options")
  }
  const state = ctx.methodState
  const form = await safeForm(ctx.request)
  const parsed = verifyBody.safeParse(form)
  if (!parsed.success) return errorResult("missing response")
  let attestation
  try {
    attestation = JSON.parse(parsed.data.response)
  } catch {
    return errorResult("malformed WebAuthn attestation")
  }

  let verification
  try {
    verification = await verifyRegistrationResponse({
      response: attestation,
      expectedChallenge: state.challenge,
      expectedOrigin: opts.origin,
      expectedRPID: opts.rpID,
      requireUserVerification: false,
    })
  } catch (e) {
    return errorResult(
      e instanceof Error ? e.message : "verification threw",
    )
  }
  if (!verification.verified || !verification.registrationInfo) {
    return errorResult("registration rejected")
  }
  const reg = verification.registrationInfo
  await opts.credentials.create({
    userId: state.userId,
    credential: {
      credentialId: reg.credential.id,
      publicKey: base64urlEncode(reg.credential.publicKey),
      counter: reg.credential.counter,
      ...(reg.credential.transports
        ? { transports: reg.credential.transports as string[] }
        : {}),
      userId: state.userId,
    },
    tenantId: ctx.tenant.id,
  })
  return {
    kind: "success",
    providerSubject: state.userId,
    properties: { userId: state.userId, credentialId: reg.credential.id },
  }
}

function errorResult(
  description: string,
): MethodResult<PasskeyProperties, PasskeyState> {
  return {
    kind: "error",
    error: { code: "invalid_request", description },
  }
}

async function safeForm(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? ""
  if (ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return Object.fromEntries(
      new URLSearchParams(await req.text()).entries(),
    )
  }
  if (ct.toLowerCase().startsWith("application/json")) {
    try {
      return (await req.json()) as Record<string, string>
    } catch {
      return {}
    }
  }
  return {}
}

function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  })
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function base64urlEncode(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function base64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4)
  const b64 = (s + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/")
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
