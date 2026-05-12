/**
 * In-memory `KmsBackingStore`. Used by the KMS adapter conformance test and
 * for single-instance dev. Production deployments pass a real backing store
 * (Postgres, DynamoDB, S3-with-versioning, etc.) so KMS-wrapped key
 * envelopes survive process restarts.
 */
import type {
  KmsBackingStore,
  WrappedEncryptionKey,
  WrappedSigningKey,
} from "./types"

export function inMemoryKmsBackingStore(): KmsBackingStore {
  const signing = new Map<string, WrappedSigningKey>()
  const encryption = new Map<string, WrappedEncryptionKey>()
  return {
    async putSigningKey(row) {
      signing.set(row.kid, row)
    },
    async getSigningKey(kid) {
      return signing.get(kid)
    },
    async listSigningKeys() {
      return Array.from(signing.values())
    },
    async putEncryptionKey(row) {
      encryption.set(row.kid, row)
    },
    async getEncryptionKey(kid) {
      return encryption.get(kid)
    },
    async listEncryptionKeys() {
      return Array.from(encryption.values())
    },
  }
}
