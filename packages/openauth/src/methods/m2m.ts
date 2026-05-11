/**
 * `m2mMethod` — machine-to-machine factory (RFC 6749 §4.4 client_credentials).
 *
 * No URL routes. The factory ships only a `client` fn the framework invokes
 * from `/token` after standard client authentication has succeeded. The
 * fn validates and returns the `P` properties the success callback will
 * map into the issued subject claim.
 *
 * Typical use: a tenant configures one m2m method instance per tenant.
 * The user-supplied `verify` hook decides whether the (already
 * authenticated) client is allowed to use this method and what claims it
 * carries (org id, service tier, etc.).
 */
import { z } from "zod"

import { authError } from "../types/error"
import { err, ok, type Result } from "../types/result"
import type {
  AuthMethod,
  AuthMethodFactory,
  ClientFn,
} from "../types/method"

export type M2MProperties = {
  /** The client's stable id (echoed back from the request). */
  clientId: string
  /** Tenant-supplied extra claims. */
  claims?: Record<string, unknown>
}

export type M2MMethodOptions = {
  /**
   * Look up the client's per-client metadata. Return `null` for unauthorized
   * (the framework already authenticated the secret; this is for
   * application-level authorization — e.g. "is this client allowed to use
   * this method?", "what claims should we attach?").
   */
  verify: (input: {
    clientID: string
    params: Record<string, string>
    tenantId: string
  }) => Promise<{ claims?: Record<string, unknown> } | null>
}

const configSchema = z.object({}).strict()
type M2MConfig = z.infer<typeof configSchema>

export function m2mMethod(
  opts: M2MMethodOptions,
): AuthMethodFactory<M2MProperties, never, M2MConfig> {
  return {
    kind: "m2m",
    configSchema,
    build: async ({ id, kind, tenantId }): Promise<AuthMethod<M2MProperties, never>> => {
      const clientFn: ClientFn<M2MProperties> = async (input): Promise<
        Result<M2MProperties, ReturnType<typeof authError.invalidClient>>
      > => {
        const verified = await opts.verify({
          clientID: input.clientID,
          params: input.params,
          tenantId,
        })
        if (!verified) {
          return err(authError.invalidClient("client not authorized for m2m"))
        }
        return ok({
          clientId: input.clientID,
          ...(verified.claims ? { claims: verified.claims } : {}),
        })
      }
      return {
        id,
        kind,
        type: "m2m",
        routes: {},
        client: clientFn,
      }
    },
  }
}
