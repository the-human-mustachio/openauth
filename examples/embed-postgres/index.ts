/**
 * Minimum-viable embedding example: Node/Bun + Postgres.
 *
 * Stands up an IdP with password + Google sign-in over a single
 * Postgres instance. Run against a Postgres URL in DATABASE_URL.
 *
 * This is the full text of INTEGRATION.md § 7 made runnable. For the
 * embedding contract (the four host-side surfaces, behavioral rules,
 * hardening), read INTEGRATION.md first.
 */
import { randomBytes } from "node:crypto"
import postgres from "postgres"
import { z } from "zod"
import {
  asTenantId,
  authError,
  createIdP,
  err,
  googleFactory,
  ok,
  passwordMethod,
  type StateKeyRing,
  type SubjectClaim,
  type SubjectSchema,
  type SuccessMapInput,
} from "@_mustachio/openauth"
import {
  fromPostgresJs,
  migrate,
  PostgresAuditLog,
  PostgresConfigStore,
  PostgresKeyStore,
  PostgresMethodStore,
  PostgresSessionStore,
  PostgresTokenStore,
} from "@_mustachio/openauth/adapters/postgres"

// ─── 1. Storage ────────────────────────────────────────────────────────────

const sql = postgres(process.env.DATABASE_URL!)
const exec = fromPostgresJs(sql as never)
await migrate(exec) // idempotent — creates tables on first run

const keyStore = new PostgresKeyStore({ exec })

// ─── 2. Toy in-memory "host" stores (replace with your real DB) ────────────

const users = new Map<string, { id: string; email: string }>()
const upsertUser = async ({
  providerSubject,
  email,
}: {
  providerSubject: string
  email: string
}) => {
  const existing = users.get(providerSubject)
  if (existing) return existing
  const fresh = { id: crypto.randomUUID(), email }
  users.set(providerSubject, fresh)
  return fresh
}

// ─── 3. State-MAC key ring ─────────────────────────────────────────────────

const stateKeys: StateKeyRing = {
  active: {
    kid: new Date().toISOString().slice(0, 7), // YYYY-MM
    key: new Uint8Array(randomBytes(32)),
  },
  verify: [], // populate `active` here too, plus previous keys in overlap window
}
stateKeys.verify = [stateKeys.active]

// ─── 4. Subject schema ─────────────────────────────────────────────────────

const subjects = {
  user: z.object({
    userId: z.string(),
    email: z.string().email(),
  }),
} satisfies SubjectSchema

// ─── 5. Compose ────────────────────────────────────────────────────────────

const idp = createIdP({
  resolveTenant: async (req) => {
    const clientId = new URL(req.url).searchParams.get("client_id")
    if (!clientId) return err(authError.invalidRequest("missing client_id"))
    return ok(asTenantId(clientId))
  },

  stateKeys,

  configStore: new PostgresConfigStore({ exec }),
  tokenStore: new PostgresTokenStore({ exec, keyStore }),
  sessionStore: new PostgresSessionStore({ exec }),
  methodStore: new PostgresMethodStore({ exec }),
  auditLog: new PostgresAuditLog({ exec }),
  keyStore,

  issuerUrl: process.env.ISSUER_URL ?? "http://localhost:3000",

  methods: {
    password: passwordMethod({
      users: {
        // Wire to your real user store. Signature is positional:
        // (email, tenantId) → PasswordUser | null.
        async findByEmail(email, _tenantId) {
          for (const u of users.values())
            if (u.email === email) return u as never
          return null
        },
      },
    }),
    google: googleFactory,
  },

  subjects,

  success: async ({
    providerSubject,
    properties,
  }: SuccessMapInput): Promise<SubjectClaim> => {
    const email = (properties as { email?: string }).email ?? ""
    const user = await upsertUser({ providerSubject, email })
    return { type: "user", properties: { userId: user.id, email: user.email } }
  },
})

// ─── 6. Serve ──────────────────────────────────────────────────────────────

Bun.serve({
  port: Number(process.env.PORT ?? 3000),
  fetch: idp.handle,
})

console.log(
  `IdP listening on http://localhost:${process.env.PORT ?? 3000}`,
  `\n  • /.well-known/openid-configuration`,
  `\n  • /authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256`,
)
