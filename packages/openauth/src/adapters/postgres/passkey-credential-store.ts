/**
 * Postgres `PasskeyCredentialStore`.
 *
 * Schema (created by `migrate()` in `./migrations.ts`):
 *
 *   openauth_passkey_credentials
 *     tenant_id   text  NOT NULL
 *     credential_id text NOT NULL
 *     user_id     text  NOT NULL
 *     public_key  text  NOT NULL
 *     counter     bigint NOT NULL DEFAULT 0
 *     transports  jsonb
 *     created_at  bigint NOT NULL
 *     PRIMARY KEY (tenant_id, credential_id)
 *     INDEX (tenant_id, user_id)   -- findByUsername path
 *
 * The reference adapter treats `userId` as the username lookup key —
 * matching the bundled `passkeyMethod` which sets `userId =
 * parsed.data.username` at registration. Hosts that want a separate
 * username dimension implement `PasskeyCredentialStore` directly
 * against their own user table.
 */
import type {
  PasskeyCredentialStore,
  StoredCredential,
} from "../../methods/passkey"

import type { PostgresExecutor } from "./executor"

export type PostgresPasskeyCredentialStoreOptions = {
  exec: PostgresExecutor
  clock?: () => number
}

type Row = {
  credential_id: string
  user_id: string
  public_key: string
  counter: string | number
  transports: unknown
}

export class PostgresPasskeyCredentialStore implements PasskeyCredentialStore {
  #exec: PostgresExecutor
  #clock: () => number

  constructor(opts: PostgresPasskeyCredentialStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async findByUsername(
    username: string,
    tenantId: string,
  ): Promise<{ userId: string; credentials: StoredCredential[] } | null> {
    const result = await this.#exec.query<Row>(
      `SELECT credential_id, user_id, public_key, counter, transports
         FROM openauth_passkey_credentials
        WHERE tenant_id = $1 AND user_id = $2`,
      [tenantId, username],
    )
    if (result.rows.length === 0) return null
    return {
      userId: username,
      credentials: result.rows.map(rowToCredential),
    }
  }

  async findById(
    credentialId: string,
    tenantId: string,
  ): Promise<StoredCredential | null> {
    const result = await this.#exec.query<Row>(
      `SELECT credential_id, user_id, public_key, counter, transports
         FROM openauth_passkey_credentials
        WHERE tenant_id = $1 AND credential_id = $2`,
      [tenantId, credentialId],
    )
    const row = result.rows[0]
    if (!row) return null
    return rowToCredential(row)
  }

  async updateCounter(input: {
    credentialId: string
    counter: number
    tenantId: string
  }): Promise<void> {
    await this.#exec.query(
      `UPDATE openauth_passkey_credentials
          SET counter = $1
        WHERE tenant_id = $2 AND credential_id = $3`,
      [input.counter, input.tenantId, input.credentialId],
    )
  }

  async create(input: {
    userId: string
    credential: StoredCredential
    tenantId: string
  }): Promise<void> {
    await this.#exec.query(
      `INSERT INTO openauth_passkey_credentials
         (tenant_id, credential_id, user_id, public_key, counter, transports, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
       ON CONFLICT (tenant_id, credential_id) DO UPDATE
         SET public_key = EXCLUDED.public_key,
             counter = EXCLUDED.counter,
             transports = EXCLUDED.transports,
             user_id = EXCLUDED.user_id`,
      [
        input.tenantId,
        input.credential.credentialId,
        input.userId,
        input.credential.publicKey,
        input.credential.counter,
        input.credential.transports
          ? JSON.stringify(input.credential.transports)
          : null,
        this.#clock(),
      ],
    )
  }
}

function rowToCredential(row: Row): StoredCredential {
  const credential: StoredCredential = {
    credentialId: row.credential_id,
    publicKey: row.public_key,
    counter: Number(row.counter),
    userId: row.user_id,
  }
  if (row.transports != null) {
    credential.transports = parseTransports(row.transports)
  }
  return credential
}

function parseTransports(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.map(String)
  if (typeof raw === "string") {
    try {
      const parsed: unknown = JSON.parse(raw)
      return Array.isArray(parsed) ? parsed.map(String) : []
    } catch {
      return []
    }
  }
  return []
}
