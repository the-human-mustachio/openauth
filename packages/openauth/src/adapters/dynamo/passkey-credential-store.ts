/**
 * DynamoDB `PasskeyCredentialStore`.
 *
 * Single-table layout, one item per credential:
 *
 *   pk = "passkey-cred"
 *   sk = "<tenantId>#<credentialId>"
 *   user_key = "<tenantId>#<userId>"       // GSI hash for findByUsername
 *   tenant_id, user_id, public_key, counter, transports, created_at
 *
 * Required GSI on the table (alongside `family-index` /
 * `subject-index` from `DynamoTokenStore`):
 *
 *   passkey-user-index
 *     Hash key: user_key (S)
 *     Projection: ALL
 *
 * The reference adapter treats `userId` as the username lookup key —
 * matching the bundled `passkeyMethod`. Hosts that need
 * username ≠ userId implement `PasskeyCredentialStore` directly.
 */
import type {
  PasskeyCredentialStore,
  StoredCredential,
} from "../../methods/passkey"

import type { DynamoExecutor } from "./client"

export type DynamoPasskeyCredentialStoreOptions = {
  exec: DynamoExecutor
  clock?: () => number
}

export class DynamoPasskeyCredentialStore implements PasskeyCredentialStore {
  #exec: DynamoExecutor
  #clock: () => number

  constructor(opts: DynamoPasskeyCredentialStoreOptions) {
    this.#exec = opts.exec
    this.#clock = opts.clock ?? (() => Date.now())
  }

  async findByUsername(
    username: string,
    tenantId: string,
  ): Promise<{ userId: string; credentials: StoredCredential[] } | null> {
    let items: Record<string, unknown>[]
    try {
      items = await this.#exec.queryByGsi({
        indexName: "passkey-user-index",
        hashKey: userKey(tenantId, username),
      })
    } catch {
      return null
    }
    if (items.length === 0) return null
    return {
      userId: username,
      credentials: items.map(itemToCredential),
    }
  }

  async findById(
    credentialId: string,
    tenantId: string,
  ): Promise<StoredCredential | null> {
    const item = await this.#exec.get({
      key: { pk: "passkey-cred", sk: sortKey(tenantId, credentialId) },
      consistentRead: true,
    })
    if (!item) return null
    return itemToCredential(item)
  }

  async updateCounter(input: {
    credentialId: string
    counter: number
    tenantId: string
  }): Promise<void> {
    await this.#exec.updateItem({
      key: {
        pk: "passkey-cred",
        sk: sortKey(input.tenantId, input.credentialId),
      },
      set: { counter: input.counter },
    })
  }

  async create(input: {
    userId: string
    credential: StoredCredential
    tenantId: string
  }): Promise<void> {
    const item: Record<string, unknown> = {
      pk: "passkey-cred",
      sk: sortKey(input.tenantId, input.credential.credentialId),
      tenant_id: input.tenantId,
      credential_id: input.credential.credentialId,
      user_id: input.userId,
      user_key: userKey(input.tenantId, input.userId),
      public_key: input.credential.publicKey,
      counter: input.credential.counter,
      created_at: this.#clock(),
    }
    if (input.credential.transports) {
      item.transports = input.credential.transports
    }
    await this.#exec.put({ item: item as never })
  }
}

function sortKey(tenantId: string, credentialId: string): string {
  return `${tenantId}#${credentialId}`
}

function userKey(tenantId: string, userId: string): string {
  return `${tenantId}#${userId}`
}

function itemToCredential(item: Record<string, unknown>): StoredCredential {
  const credential: StoredCredential = {
    credentialId: String(item.credential_id ?? ""),
    publicKey: String(item.public_key ?? ""),
    counter: Number(item.counter ?? 0),
    userId: String(item.user_id ?? ""),
  }
  const transports = item.transports
  if (Array.isArray(transports)) {
    credential.transports = transports.map(String)
  }
  return credential
}
