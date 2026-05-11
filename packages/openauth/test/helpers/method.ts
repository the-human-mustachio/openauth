/**
 * Test helpers — stub `AuthMethodFactory` instances used by domain tests
 * before Phases 4–5 provide real methods.
 */
import { z } from "zod"

import type {
  AuthMethod,
  AuthMethodFactory,
  MethodContext,
  MethodResult,
} from "../../src/types/method"

export type StubProps = { handle: string }

/**
 * A factory that builds a method whose `GET /authorize` handler returns a
 * `success` MethodResult immediately — useful for testing the
 * single-step / credential-flow branch of `startAuthorize`.
 */
export function inlineSuccessFactory(opts: {
  kind: string
  providerSubject?: string
  properties?: StubProps
}): AuthMethodFactory<StubProps, unknown, { tag?: string }> {
  return {
    kind: opts.kind,
    configSchema: z.object({ tag: z.string().optional() }),
    build: async ({ id, kind }): Promise<AuthMethod<StubProps, unknown>> => ({
      id,
      kind,
      type: "custom",
      routes: {
        "GET /authorize": async (_ctx: MethodContext<unknown>) =>
          ({
            kind: "success",
            providerSubject: opts.providerSubject ?? "test-subject",
            properties: opts.properties ?? { handle: "ada" },
          }) satisfies MethodResult<StubProps, unknown>,
      },
    }),
  }
}

/**
 * A factory that builds a method whose `GET /authorize` returns a redirect
 * `challenge` and whose `GET /callback` returns `success` after reading
 * `methodState`. Useful for the full authorize → callback flow test.
 */
export function redirectFactory(opts: {
  kind: string
  providerSubject?: string
  properties?: StubProps
}): AuthMethodFactory<StubProps, { upstreamNonce: string }, {}> {
  return {
    kind: opts.kind,
    configSchema: z.object({}).strict(),
    build: async ({
      id,
      kind,
    }): Promise<AuthMethod<StubProps, { upstreamNonce: string }>> => ({
      id,
      kind,
      type: "oauth2",
      routes: {
        "GET /authorize": async (ctx) => {
          const upstream = new URL(
            ctx.dispatch ? "https://upstream.example/auth" : "about:blank",
          )
          if (ctx.dispatch) {
            upstream.searchParams.set("state", ctx.dispatch.state)
            upstream.searchParams.set("redirect_uri", ctx.dispatch.callbackUrl)
          }
          return {
            kind: "challenge",
            response: new Response(null, {
              status: 302,
              headers: { location: upstream.toString() },
            }),
            saveMethodState: { upstreamNonce: "abc123" },
          }
        },
        "GET /callback": async (_ctx) => ({
          kind: "success",
          providerSubject: opts.providerSubject ?? "upstream-subject",
          properties: opts.properties ?? { handle: "ada" },
        }),
      },
    }),
  }
}

/** Factory that ALWAYS returns `denied`. */
export function deniedFactory(
  kind: string,
): AuthMethodFactory<StubProps, unknown, {}> {
  return {
    kind,
    configSchema: z.object({}).strict(),
    build: async ({
      id,
      kind: k,
    }): Promise<AuthMethod<StubProps, unknown>> => ({
      id,
      kind: k,
      type: "custom",
      routes: {
        "GET /authorize": async () => ({
          kind: "denied",
          reason: "user_declined",
        }),
      },
    }),
  }
}

/** Factory whose returned AuthMethod has a mismatched `id` — triggers `factory_id_mismatch`. */
export function brokenIdFactory(
  kind: string,
): AuthMethodFactory<StubProps, unknown, {}> {
  return {
    kind,
    configSchema: z.object({}).strict(),
    build: async (): Promise<AuthMethod<StubProps, unknown>> => ({
      id: "WRONG_ID",
      kind: "WRONG_KIND",
      type: "custom",
      routes: {},
    }),
  }
}
