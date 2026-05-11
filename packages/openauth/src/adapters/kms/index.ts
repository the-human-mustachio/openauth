/**
 * KMS-backed `KeyStore` adapter set.
 *
 * Envelope encryption: private JWK material is wrapped under an AWS KMS
 * master key and stored in a pluggable backing store (`KmsBackingStore`).
 * KMS Encrypt / Decrypt are the only KMS operations on the hot path; the
 * framework still receives a real `CryptoKey` for JWT signing so no surgery
 * in `domain/jwt.ts` is needed.
 *
 * @example
 *   import { KMSClient } from "@aws-sdk/client-kms"
 *   import {
 *     fromKmsClient,
 *     inMemoryKmsBackingStore,
 *     KmsKeyStore,
 *   } from "@_mustachio/openauth/adapters/kms"
 *
 *   const kms = fromKmsClient(
 *     new KMSClient({ region: "us-east-1" }),
 *     process.env.IDP_KMS_KEY_ARN!,
 *   )
 *   // For production, swap in a persistent KmsBackingStore (Postgres,
 *   // DynamoDB, etc.). The in-memory store is appropriate for single-instance
 *   // dev only.
 *   const keyStore = new KmsKeyStore({ kms, backing: inMemoryKmsBackingStore() })
 *
 * Operators with strict no-plaintext-cache requirements can disable the
 * unwrapped-key cache via `cacheUnwrappedKeys: false` — every read then
 * round-trips to KMS.
 */
export { inMemoryKmsBackingStore } from "./in-memory-backing"
export { KmsKeyStore, type KmsKeyStoreOptions } from "./key-store"
export { fromKmsClient } from "./sdk"
export type {
  KmsBackingStore,
  KmsClientLike,
  WrappedEncryptionKey,
  WrappedSigningKey,
} from "./types"
