/**
 * In-memory `PasskeyCredentialStore`. Map-backed, single-process —
 * suitable for tests and single-instance dev.
 *
 * Schema simplification (shared by all three reference adapters): the
 * `userId` field is also the username lookup key. This matches the
 * bundled `passkeyMethod`, which sets `userId = parsed.data.username`
 * at registration time. Hosts that need a richer mapping
 * (username ≠ userId, multi-username-per-user, etc.) implement
 * `PasskeyCredentialStore` directly against their own data model.
 */
import type {
  PasskeyCredentialStore,
  StoredCredential,
} from "../../methods/passkey"

export type MemoryPasskeyCredentialStoreOptions = {
  /**
   * Optional seed list for tests / dev. Each entry is the full
   * `StoredCredential` plus its tenant scope. The store treats the
   * credential's `userId` as the username lookup key.
   */
  seed?: Array<{ tenantId: string; credential: StoredCredential }>
}

export class MemoryPasskeyCredentialStore implements PasskeyCredentialStore {
  #items = new Map<string, StoredCredential & { tenantId: string }>()

  constructor(opts: MemoryPasskeyCredentialStoreOptions = {}) {
    for (const entry of opts.seed ?? []) {
      this.#items.set(this.#key(entry.tenantId, entry.credential.credentialId), {
        ...entry.credential,
        tenantId: entry.tenantId,
      })
    }
  }

  #key(tenantId: string, credentialId: string): string {
    return `${tenantId}|${credentialId}`
  }

  async findByUsername(
    username: string,
    tenantId: string,
  ): Promise<{ userId: string; credentials: StoredCredential[] } | null> {
    const credentials: StoredCredential[] = []
    for (const item of this.#items.values()) {
      if (item.tenantId !== tenantId) continue
      if (item.userId !== username) continue
      credentials.push(stripTenant(item))
    }
    if (credentials.length === 0) return null
    return { userId: username, credentials }
  }

  async findById(
    credentialId: string,
    tenantId: string,
  ): Promise<StoredCredential | null> {
    const item = this.#items.get(this.#key(tenantId, credentialId))
    return item ? stripTenant(item) : null
  }

  async updateCounter(input: {
    credentialId: string
    counter: number
    tenantId: string
  }): Promise<void> {
    const k = this.#key(input.tenantId, input.credentialId)
    const item = this.#items.get(k)
    if (!item) return
    this.#items.set(k, { ...item, counter: input.counter })
  }

  async create(input: {
    userId: string
    credential: StoredCredential
    tenantId: string
  }): Promise<void> {
    this.#items.set(
      this.#key(input.tenantId, input.credential.credentialId),
      {
        ...input.credential,
        userId: input.userId,
        tenantId: input.tenantId,
      },
    )
  }
}

function stripTenant(
  item: StoredCredential & { tenantId: string },
): StoredCredential {
  const { tenantId: _unused, ...rest } = item
  void _unused
  return rest
}
