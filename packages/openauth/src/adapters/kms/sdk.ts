/**
 * `fromKmsClient` — wires the `KmsClientLike` interface to a real AWS KMS
 * client. The KMS SDK is imported only from this file to keep the rest of
 * the adapter bundle KMS-agnostic.
 *
 * @example
 *   import { KMSClient } from "@aws-sdk/client-kms"
 *   const kmsClient = new KMSClient({ region: "us-east-1" })
 *   const kms = fromKmsClient(kmsClient, process.env.IDP_KMS_KEY_ARN!)
 *   const backing = new PostgresKmsBackingStore({ exec })
 *   const keyStore = new KmsKeyStore({ kms, backing })
 */
import type { KMSClient } from "@aws-sdk/client-kms"
import { DecryptCommand, EncryptCommand } from "@aws-sdk/client-kms"

import type { KmsClientLike } from "./types"

export function fromKmsClient(
  client: KMSClient,
  keyId: string,
): KmsClientLike {
  return {
    async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
      const result = await client.send(
        new EncryptCommand({ KeyId: keyId, Plaintext: plaintext }),
      )
      if (!result.CiphertextBlob) {
        throw new Error("KMS Encrypt returned no ciphertext")
      }
      return new Uint8Array(result.CiphertextBlob)
    },
    async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
      const result = await client.send(
        new DecryptCommand({ KeyId: keyId, CiphertextBlob: ciphertext }),
      )
      if (!result.Plaintext) {
        throw new Error("KMS Decrypt returned no plaintext")
      }
      return new Uint8Array(result.Plaintext)
    },
  }
}
