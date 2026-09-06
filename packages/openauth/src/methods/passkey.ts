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
import { mountedPath } from "../domain/mount"
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
  /**
   * Tenant-supplied credential store. The framework calls into it for
   * lookups + writes; it knows nothing about how credentials are stored.
   */
  credentials: PasskeyCredentialStore
}

export type PasskeyState =
  | { phase: "auth"; challenge: string; username: string }
  | { phase: "register"; challenge: string; userId: string; username: string }

/**
 * Per-tenant config. `rpID` is the WebAuthn Relying Party ID (the
 * registrable domain — e.g. `"acme.example"`); each tenant typically
 * runs on its own domain so this is per-tenant, not per-factory.
 *
 * `origins` is the list of accepted browser origins (HTTPS URLs).
 * Multi-origin support is useful for tenants with both an app subdomain
 * and a marketing domain that both terminate at the IdP.
 */
const configSchema = z.object({
  /** Display name shown by the authenticator UI. */
  rpName: z.string().min(1),
  /** Relying Party ID — the registrable domain. */
  rpID: z.string().min(1),
  /** Accepted origin(s). Either a single URL or an array of URLs. */
  origins: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  /** Form title override. */
  title: z.string().optional(),
})
type PasskeyConfig = z.infer<typeof configSchema>

/**
 * Resolved per-instance settings threaded into route handlers. We
 * collapse the union shape of `origins` into the array shape
 * `@simplewebauthn/server` accepts.
 */
type PasskeySettings = {
  rpName: string
  rpID: string
  origin: string | string[]
  title: string
  credentials: PasskeyCredentialStore
}

const usernameBody = z.object({ username: z.string().min(1) })
const verifyBody = z.object({ response: z.string().min(1) })

export function passkeyMethod(
  opts: PasskeyMethodOptions,
): AuthMethodFactory<PasskeyProperties, PasskeyState, PasskeyConfig> {
  return {
    kind: "passkey",
    configSchema,
    build: async ({
      id,
      kind,
      config,
    }): Promise<AuthMethod<PasskeyProperties, PasskeyState>> => {
      const settings: PasskeySettings = {
        rpName: config.rpName,
        rpID: config.rpID,
        origin: config.origins,
        title: config.title ?? "Sign in with passkey",
        credentials: opts.credentials,
      }
      return {
        id,
        kind,
        type: "passkey",
        routes: {
          "GET /authorize": async (ctx) => ({
            kind: "challenge",
            response: htmlResponse(
              renderForm({
                title: settings.title,
                action: mountedPath(
                  ctx.issuerUrl,
                  `/m/${id}/authenticate-options`,
                ),
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
            authOptions(ctx, settings),
          "POST /authenticate-verify": async (ctx) => authVerify(ctx, settings),
          "POST /register-options": async (ctx) =>
            registerOptions(ctx, id, settings),
          "POST /register-verify": async (ctx) => registerVerify(ctx, settings),
        },
      }
    },
  }
}

async function authOptions(
  ctx: MethodContext<PasskeyState>,
  settings: PasskeySettings,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  const form = await safeForm(ctx.request)
  const parsed = usernameBody.safeParse(form)
  if (!parsed.success) {
    return errorResult("missing username")
  }
  const found = await settings.credentials.findByUsername(
    parsed.data.username,
    ctx.tenant.id,
  )
  if (!found) {
    return errorResult("unknown user")
  }
  const options = await generateAuthenticationOptions({
    rpID: settings.rpID,
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
  settings: PasskeySettings,
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
  const stored = await settings.credentials.findById(
    credentialId,
    ctx.tenant.id,
  )
  if (!stored) return errorResult("unknown credential")

  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: state.challenge,
      expectedOrigin: settings.origin,
      expectedRPID: settings.rpID,
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
    return errorResult(e instanceof Error ? e.message : "verification threw")
  }
  if (!verification.verified) {
    return errorResult("verification rejected")
  }
  await settings.credentials.updateCounter({
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
  settings: PasskeySettings,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  if (!settings.credentials.create) {
    return errorResult("registration not enabled")
  }
  const form = await safeForm(ctx.request)
  const parsed = usernameBody.safeParse(form)
  if (!parsed.success) return errorResult("missing username")

  const userId = parsed.data.username
  const options = await generateRegistrationOptions({
    rpName: settings.rpName,
    rpID: settings.rpID,
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
  settings: PasskeySettings,
): Promise<MethodResult<PasskeyProperties, PasskeyState>> {
  if (!settings.credentials.create) {
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
      expectedOrigin: settings.origin,
      expectedRPID: settings.rpID,
      requireUserVerification: false,
    })
  } catch (e) {
    return errorResult(e instanceof Error ? e.message : "verification threw")
  }
  if (!verification.verified || !verification.registrationInfo) {
    return errorResult("registration rejected")
  }
  const reg = verification.registrationInfo
  await settings.credentials.create({
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
    return Object.fromEntries(new URLSearchParams(await req.text()).entries())
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
