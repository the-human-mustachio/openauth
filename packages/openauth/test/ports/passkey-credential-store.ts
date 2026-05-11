/**
 * Parameterized `PasskeyCredentialStore` conformance suite.
 *
 * Exercises the four-method contract on `methods/passkey.ts`:
 *
 *   findByUsername(username, tenantId)
 *   findById(credentialId, tenantId)
 *   updateCounter({ credentialId, counter, tenantId })
 *   create?({ userId, credential, tenantId })
 *
 * The shipped reference adapters (memory / postgres / dynamo) treat
 * `userId` as the username lookup key — see each adapter's JSDoc. These
 * conformance tests honour that simplification by passing the same
 * string for both.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test"

import type {
  PasskeyCredentialStore,
  StoredCredential,
} from "../../src/methods/passkey"

import { uniqueSuffix } from "./fixtures"

export type PasskeyCredentialStoreSuiteOptions = {
  adapterName: string
  makeStore: () => Promise<{
    store: PasskeyCredentialStore
    dispose?: () => Promise<void>
  }>
}

function makeCredential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    credentialId: uniqueSuffix("cred"),
    publicKey: "AAAA",
    counter: 0,
    userId: uniqueSuffix("user"),
    ...overrides,
  }
}

export function describePasskeyCredentialStore(
  opts: PasskeyCredentialStoreSuiteOptions,
): void {
  describe(`PasskeyCredentialStore conformance — ${opts.adapterName}`, () => {
    let store: PasskeyCredentialStore
    let dispose: (() => Promise<void>) | undefined

    beforeEach(async () => {
      const built = await opts.makeStore()
      store = built.store
      dispose = built.dispose
    })

    afterEach(async () => {
      if (dispose) await dispose()
    })

    test("create + findById round-trips a credential", async () => {
      const tenantId = uniqueSuffix("t")
      const credential = makeCredential()
      await store.create!({
        userId: credential.userId,
        credential,
        tenantId,
      })
      const got = await store.findById(credential.credentialId, tenantId)
      expect(got).not.toBeNull()
      if (got) {
        expect(got.credentialId).toBe(credential.credentialId)
        expect(got.publicKey).toBe(credential.publicKey)
        expect(got.counter).toBe(0)
        expect(got.userId).toBe(credential.userId)
      }
    })

    test("findById of unknown credential returns null", async () => {
      const tenantId = uniqueSuffix("t")
      const got = await store.findById(uniqueSuffix("nope"), tenantId)
      expect(got).toBeNull()
    })

    test("findByUsername returns all credentials for that user", async () => {
      const tenantId = uniqueSuffix("t")
      const userId = uniqueSuffix("user")
      const c1 = makeCredential({ userId })
      const c2 = makeCredential({ userId })
      await store.create!({ userId, credential: c1, tenantId })
      await store.create!({ userId, credential: c2, tenantId })
      const got = await store.findByUsername(userId, tenantId)
      expect(got).not.toBeNull()
      if (got) {
        expect(got.userId).toBe(userId)
        const ids = got.credentials.map((c) => c.credentialId).sort()
        expect(ids).toEqual([c1.credentialId, c2.credentialId].sort())
      }
    })

    test("findByUsername of unknown user returns null", async () => {
      const tenantId = uniqueSuffix("t")
      const got = await store.findByUsername(uniqueSuffix("nope"), tenantId)
      expect(got).toBeNull()
    })

    test("findByUsername scopes to tenant", async () => {
      const tenantA = uniqueSuffix("ta")
      const tenantB = uniqueSuffix("tb")
      const credential = makeCredential()
      await store.create!({
        userId: credential.userId,
        credential,
        tenantId: tenantA,
      })
      const wrongTenant = await store.findByUsername(
        credential.userId,
        tenantB,
      )
      expect(wrongTenant).toBeNull()
      // And findById is also tenant-scoped.
      const wrongTenantById = await store.findById(
        credential.credentialId,
        tenantB,
      )
      expect(wrongTenantById).toBeNull()
    })

    test("updateCounter advances the stored counter", async () => {
      const tenantId = uniqueSuffix("t")
      const credential = makeCredential()
      await store.create!({
        userId: credential.userId,
        credential,
        tenantId,
      })
      await store.updateCounter({
        credentialId: credential.credentialId,
        counter: 42,
        tenantId,
      })
      const got = await store.findById(credential.credentialId, tenantId)
      expect(got?.counter).toBe(42)
    })

    test("updateCounter for unknown credential is a no-op (does not throw)", async () => {
      const tenantId = uniqueSuffix("t")
      await store.updateCounter({
        credentialId: uniqueSuffix("nope"),
        counter: 5,
        tenantId,
      })
      // Reaching here without throwing is the assertion.
      expect(true).toBe(true)
    })

    test("transports round-trip when present", async () => {
      const tenantId = uniqueSuffix("t")
      const credential = makeCredential({
        transports: ["internal", "hybrid"],
      })
      await store.create!({
        userId: credential.userId,
        credential,
        tenantId,
      })
      const got = await store.findById(credential.credentialId, tenantId)
      expect(got?.transports).toEqual(["internal", "hybrid"])
    })
  })
}
