import { Provider } from "./provider.js"

export interface M2MProviderConfig {
  /**
   * Callback to verify client credentials.
   * Should return data about the client (e.g., associated User or Org ID).
   * Returning undefined or throwing indicates invalid credentials.
   */
  verify: (
    clientID: string,
    clientSecret: string,
    params: Record<string, string>,
  ) => Promise<
    | {
        id: string
        [key: string]: any
      }
    | undefined
  >
}

/**
 * Creates a provider for Machine-to-Machine (M2M) authentication using the
 * OAuth 2.0 `client_credentials` grant type.
 *
 * This provider does not have a UI and is intended for service-to-service
 * communication where the client can securely store a secret.
 *
 * @example
 * ```ts
 * const m2m = M2MProvider({
 *   verify: async (clientID, clientSecret) => {
 *     const client = await db.clients.findUnique({ where: { clientID } })
 *     if (client && client.secret === clientSecret) return client
 *   }
 * })
 * ```
 */
export function M2MProvider(config: M2MProviderConfig): Provider<{
  id: string
  [key: string]: any
}> {
  return {
    type: "m2m",
    init() {},
    async client(input) {
      const result = await config.verify(
        input.clientID,
        input.clientSecret,
        input.params,
      )
      if (!result) throw new Error("Invalid client credentials")
      return result
    },
  }
}
