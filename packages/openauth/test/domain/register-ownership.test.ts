/**
 * Dynamic Client Registration — the framework mints, the host persists.
 *
 * Before 0.14.0 `registerNewClient` generated a client id, a secret, its
 * hash and a complete `ClientConfig`, handed the hook only
 * `{ tenant, request }`, and then discarded all of it (`void clientConfig`).
 * Every host had to reimplement entropy, hashing, and the `ClientConfig`
 * discriminated union — while `ARCHITECTURE.md` and the `RegisterClient`
 * JSDoc both said the framework supplied them. The JSDoc contradicted its
 * own type signature one line below.
 *
 * Credential generation is protocol and security work, so it stays in the
 * library; the host still owns the table it writes to. These cover the
 * simple path (persist what you were handed) and the substitution path
 * (a host with its own id scheme), including the case where substituting
 * would otherwise hand the RP a secret that cannot authenticate.
 */
import { describe, expect, test } from "bun:test"

import { registerNewClient } from "../../src/domain/register"
import { hashClientSecret } from "../../src/domain/token"
import type { ClientConfig } from "../../src/types/tenant"
import { buildTenant, tenantContextFor } from "../helpers/tenant"

type Hook = NonNullable<
  Parameters<typeof registerNewClient>[2]["registerClient"]
>

async function run(
  hook: Hook,
  authMethod: "none" | "client_secret_basic" = "client_secret_basic",
) {
  const tenant = await buildTenant()
  return registerNewClient(
    {
      redirect_uris: ["https://app.example/cb"],
      client_name: "Test RP",
      token_endpoint_auth_method: authMethod,
    },
    tenantContextFor(tenant),
    { registerClient: hook, clock: () => 1_700_000_000_000 },
  )
}

describe("registerClient receives usable credentials", () => {
  test("the hook is handed a ready-to-persist confidential client", async () => {
    let seen: { client?: ClientConfig; secret?: string } = {}
    const res = await run(async (input) => {
      seen = { client: input.client, secret: input.secret }
      // The whole point: persist it as-is, no reimplementation.
      return { ok: true, value: { client: input.client } }
    })

    expect(res.ok).toBe(true)
    expect(seen.client).toBeDefined()
    expect(seen.client!.type).toBe("confidential")
    expect(seen.client!.id).toBeTruthy()
    expect(seen.client!.redirectUris).toEqual(["https://app.example/cb"])
    expect(seen.secret).toBeTruthy()

    // The hash on the config actually verifies the plaintext handed over.
    if (seen.client!.type !== "confidential") throw new Error("wrong type")
    expect(await hashClientSecret(seen.secret!)).toBe(seen.client!.secretHash)
  })

  test("a public client arrives with pkceRequired as a literal true", async () => {
    // The discriminated union is easy to get subtly wrong by hand, which
    // is the reason the library builds it.
    let seen: ClientConfig | undefined
    const res = await run(async (input) => {
      seen = input.client
      return { ok: true, value: { client: input.client } }
    }, "none")

    expect(res.ok).toBe(true)
    expect(seen!.type).toBe("public")
    expect((seen as { pkceRequired: boolean }).pkceRequired).toBe(true)
    // No secret is minted for a public client, and none is returned.
    if (!res.ok) return
    expect(res.value.client_secret).toBeUndefined()
  })

  test("persisting as-is returns a secret the RP can actually use", async () => {
    let hash = ""
    const res = await run(async (input) => {
      if (input.client.type === "confidential") hash = input.client.secretHash
      return { ok: true, value: { client: input.client } }
    })
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.client_secret).toBeTruthy()
    expect(await hashClientSecret(res.value.client_secret!)).toBe(hash)
  })

  test("a host may substitute its own id and secret", async () => {
    const ownSecret = "host-chosen-secret"
    const res = await run(async (input) => ({
      ok: true,
      value: {
        client: {
          ...input.client,
          id: "host-id",
          secretHash: await hashClientSecret(ownSecret),
        } as ClientConfig,
        secret: ownSecret,
      },
    }))
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.value.client_id).toBe("host-id")
    expect(res.value.client_secret).toBe(ownSecret)
  })

  test("substituting the hash without returning the plaintext is refused", async () => {
    // Otherwise the RP leaves registration holding the framework's
    // secret, which cannot verify against the host's hash — a credential
    // that silently never works.
    const res = await run(async (input) => ({
      ok: true,
      value: {
        client: {
          ...input.client,
          secretHash: await hashClientSecret("something-else"),
        } as ClientConfig,
      },
    }))
    expect(res.ok).toBe(false)
    if (res.ok) return
    expect(res.error.code).toBe("server_error")
  })
})
