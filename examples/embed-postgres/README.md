# `embed-postgres`

The smallest possible host-application embedding of `@_mustachio/openauth`,
backed by Postgres. Mirrors INTEGRATION.md § 7 — runnable.

## Run

```bash
# from this directory
export DATABASE_URL='postgres://localhost/openauth_dev'
bun install
bun run start
```

The first run creates the library's tables via the bundled migration. Hit
`http://localhost:3000/.well-known/openid-configuration` to confirm
liveness.

## What this example is, and is not

- **Is:** a steel-thread that wires every required `IdPOptions` field
  against the Postgres adapter set, with password + Google as methods.
- **Is not:** a tenant-provisioning console, a user database, or RBAC.
  Those are host concerns — see ARCHITECTURE.md § "Embedding pattern."

The in-memory `users` map in `index.ts` exists only so the `success`
callback has something to call. Replace it with your real user store
before doing anything serious.

## Reading order

1. `packages/openauth/INTEGRATION.md` — the embedding guide.
2. `packages/openauth/ARCHITECTURE.md` — the mental model.
3. `index.ts` (this dir) — code.
