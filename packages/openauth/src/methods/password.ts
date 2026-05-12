/**
 * `passwordMethod` — username + password credential factory.
 *
 * Routes:
 *   GET  /authorize   → render login form
 *   POST /login       → verify credentials
 *   POST /register    → create user + sign in
 *
 * Forgot / reset flows land in Phase 5 alongside email-sender infra (they
 * share the same `sendEmail`-style hook the magic-code method uses).
 *
 * Storage: the framework does NOT own the user record. Users supply a
 * `users` interface (lookup / create / setPassword); the method calls into
 * it. Hashes are stored via the supplied `users.setPassword` hook so apps
 * can keep them in the same row as the rest of their user data.
 *
 * Hashing: argon2id by default (`@noble/hashes/argon2`). Pluggable via
 * `passwordMethod({ hasher: customHasher })` for migrations.
 */
import { z } from "zod"

import {
  argon2idHasher,
  type PasswordHasher,
} from "./password-hash"
import type {
  AuthMethod,
  AuthMethodFactory,
  MethodContext,
  MethodResult,
} from "../types/method"
import { renderForm } from "../ui/forms"

export type PasswordProperties = {
  /** The user's lookup key (typically their email). */
  email: string
  /** Optional extra claims the user store returned alongside the record. */
  claims?: Record<string, unknown>
}

export type PasswordState = {
  /** Most-recent error message to surface on re-render. */
  error?: string
}

export type PasswordUser = {
  /** Stable internal id (provider subject). */
  id: string
  /** Argon2id-format hash. Compared via the configured hasher. */
  passwordHash: string
  /** Optional extra claims that ride along to the IdP's success callback. */
  claims?: Record<string, unknown>
}

export type PasswordUserStore = {
  /** Look up a user by email; `null` if unknown. */
  findByEmail(
    email: string,
    tenantId: string,
  ): Promise<PasswordUser | null>
  /**
   * Optional — only required if `enableRegistration: true`. Should create
   * the row and return the persisted user. Implementations decide how to
   * race with concurrent registrations.
   */
  create?(input: {
    email: string
    passwordHash: string
    tenantId: string
  }): Promise<PasswordUser>
}

export type PasswordMethodOptions = {
  /** The tenant-supplied user store. */
  users: PasswordUserStore
  /** Override the default argon2id hasher. */
  hasher?: PasswordHasher
  /** Allow `POST /register` to create new users. Default: false. */
  enableRegistration?: boolean
  /** Display title for the form. */
  title?: string
}

/** Tenant-supplied config is empty for password — users + hasher live on the factory closure. */
const configSchema = z.object({}).strict()
type PasswordConfig = z.infer<typeof configSchema>

const loginBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
})

const registerBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
})

export function passwordMethod(
  opts: PasswordMethodOptions,
): AuthMethodFactory<PasswordProperties, PasswordState, PasswordConfig> {
  const hasher = opts.hasher ?? argon2idHasher()
  const title = opts.title ?? "Sign in"

  return {
    kind: "password",
    configSchema,
    build: async ({
      id,
      kind,
    }): Promise<AuthMethod<PasswordProperties, PasswordState>> => ({
      id,
      kind,
      type: "password",
      routes: {
        "GET /authorize": async (ctx) => renderLogin(ctx, id, title),
        "POST /login": async (ctx) =>
          handleLogin(ctx, id, title, opts.users, hasher),
        "POST /register": async (ctx) => {
          if (!opts.enableRegistration || !opts.users.create) {
            return {
              kind: "error",
              error: {
                code: "invalid_request",
                description: "registration disabled",
              },
            }
          }
          return handleRegister(
            ctx,
            id,
            title,
            opts.users.create,
            opts.users,
            hasher,
          )
        },
      },
    }),
  }
}

async function renderLogin(
  ctx: MethodContext<PasswordState>,
  methodId: string,
  title: string,
): Promise<MethodResult<PasswordProperties, PasswordState>> {
  const body = renderForm({
    title,
    action: `/m/${methodId}/login`,
    fields: [
      {
        name: "email",
        label: "Email",
        type: "email",
        required: true,
        autocomplete: "username",
      },
      {
        name: "password",
        label: "Password",
        type: "password",
        required: true,
        autocomplete: "current-password",
      },
    ],
    submit: "Sign in",
    ...(ctx.methodState?.error ? { error: ctx.methodState.error } : {}),
  })
  return {
    kind: "challenge",
    response: new Response(body, {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    }),
  }
}

async function handleLogin(
  ctx: MethodContext<PasswordState>,
  methodId: string,
  title: string,
  users: PasswordUserStore,
  hasher: PasswordHasher,
): Promise<MethodResult<PasswordProperties, PasswordState>> {
  const form = await safeForm(ctx.request)
  const parsed = loginBodySchema.safeParse(form)
  if (!parsed.success) {
    return reLoginWithError(methodId, title, "Please enter your email and password.")
  }

  const user = await users.findByEmail(parsed.data.email, ctx.tenant.id)
  if (!user) {
    return reLoginWithError(methodId, title, "Invalid email or password.")
  }

  const verified = await hasher.verify(parsed.data.password, user.passwordHash)
  if (!verified) {
    return reLoginWithError(methodId, title, "Invalid email or password.")
  }

  return {
    kind: "success",
    providerSubject: user.id,
    properties: {
      email: parsed.data.email,
      ...(user.claims ? { claims: user.claims } : {}),
    },
  }
}

async function handleRegister(
  ctx: MethodContext<PasswordState>,
  methodId: string,
  title: string,
  create: NonNullable<PasswordUserStore["create"]>,
  users: PasswordUserStore,
  hasher: PasswordHasher,
): Promise<MethodResult<PasswordProperties, PasswordState>> {
  const form = await safeForm(ctx.request)
  const parsed = registerBodySchema.safeParse(form)
  if (!parsed.success) {
    return reLoginWithError(
      methodId,
      title,
      "Password must be at least 8 characters and email must be valid.",
    )
  }

  const existing = await users.findByEmail(parsed.data.email, ctx.tenant.id)
  if (existing) {
    return reLoginWithError(
      methodId,
      title,
      "An account with that email already exists.",
    )
  }

  const passwordHash = await hasher.hash(parsed.data.password)
  const user = await create({
    email: parsed.data.email,
    passwordHash,
    tenantId: ctx.tenant.id,
  })
  return {
    kind: "success",
    providerSubject: user.id,
    properties: {
      email: parsed.data.email,
      ...(user.claims ? { claims: user.claims } : {}),
    },
  }
}

function reLoginWithError(
  methodId: string,
  title: string,
  error: string,
): MethodResult<PasswordProperties, PasswordState> {
  return {
    kind: "challenge",
    response: new Response(
      renderForm({
        title,
        action: `/m/${methodId}/login`,
        fields: [
          {
            name: "email",
            label: "Email",
            type: "email",
            required: true,
            autocomplete: "username",
          },
          {
            name: "password",
            label: "Password",
            type: "password",
            required: true,
            autocomplete: "current-password",
          },
        ],
        submit: "Sign in",
        error,
      }),
      {
        status: 400,
        headers: { "content-type": "text/html; charset=utf-8" },
      },
    ),
    saveMethodState: { error },
  }
}

async function safeForm(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? ""
  if (!ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return {}
  }
  const params = new URLSearchParams(await req.text())
  return Object.fromEntries(params.entries())
}
