/**
 * `AuthMethod` — the core pluggable authentication abstraction.
 *
 * AD2: methods are **data + handler functions**, not framework modules. They
 * depend on Web Fetch `Request`/`Response` (Web standards available on every
 * runtime) and on a small `MethodContext` of plain data. The full allowed
 * import set for files under `src/methods/` is `src/types/`,
 * `src/domain/crypto`, `src/ui/forms`, sibling `src/methods/*`, and
 * method-specific third-party libraries (e.g. `zod`,
 * `@simplewebauthn/server`); methods MUST NOT import from `src/http/`,
 * `src/adapters/`, or `src/ports/`, and never from Hono or any other HTTP
 * framework. This `types/method.ts` file in particular is enforced
 * framework-import-free by CI lint. See ARCHITECTURE.md §"Methods plug
 * in alongside this stack" for the full contract.
 *
 * Cookies and other policy-sensitive response headers are returned as data
 * (`SetCookie[]`, `CachePolicy`) and applied to the final `Response` by the
 * HTTP layer. The HTTP layer also strips a fixed allowlist-violating set of
 * headers from method-returned `Response` instances (`Set-Cookie`, security
 * headers, `Cache-Control`) so methods cannot bypass framework policy. See
 * `ARCHITECTURE.md` §"Response sanitization".
 */
import type { v1 } from "@standard-schema/spec"

import type { AuthError } from "./error"
import type { FlowRecord } from "./flow"
import type { Result } from "./result"
import type { MethodType, TenantContext, TenantId } from "./tenant"

/**
 * A built, ready-to-dispatch auth method instance for a particular tenant.
 *
 * Generics:
 *   - `P`: properties type emitted to the user's `success` callback on a
 *     successful authentication. Typed per method.
 *   - `S`: method-private state stashed in `FlowRecord.methodState`. Opaque
 *     to the framework; the method reads and writes it through
 *     `MethodContext.methodState` and `MethodResult.challenge.saveMethodState`.
 */
export type AuthMethod<P = unknown, S = unknown> = {
  /**
   * Tenant-local instance id. Populated by the factory from
   * `MethodConfig.id`. The framework dispatches URL routes by this value.
   */
  id: string
  /**
   * Factory kind. Populated by the factory from `MethodConfig.kind`. Used to
   * tell the user's `success` callback which provider produced the result.
   */
  kind: string
  type: MethodType
  /**
   * Routes the method declares. Key format: `"GET /authorize"`,
   * `"POST /callback"`, etc. The HTTP layer mounts these under
   * `/<AuthMethod.id>/*` (tenant-local instance id, so two instances of the
   * same factory get distinct URL spaces).
   */
  routes: Record<string, MethodHandler<P, S>>
  /**
   * Token-exchange function for the `/token` endpoint when the method
   * participates in client-credentials-style flows (e.g. `m2m`). Most
   * redirect-based methods do not set this.
   */
  client?: ClientFn<P>
}

export type MethodHandler<P, S> = (
  ctx: MethodContext<S>,
) => Promise<MethodResult<P, S>>

/**
 * Per-request context handed to a method handler.
 *
 * Methods **do not** receive raw `MethodConfig.config`. The factory captured
 * the validated config via closure in `build`, so the handler only sees
 * request-scoped data here.
 *
 * `cookies` is `ReadonlyMap` because methods don't get to mutate the
 * incoming cookie jar — they return `SetCookie[]` instructions and the
 * framework applies them.
 */
export type MethodContext<S = unknown> = {
  /** The raw Web Fetch `Request`. Web standard, not Hono `Context`. */
  request: Request
  /** Path within the method's mount, e.g. `"/callback"` (without the `/<id>` prefix). */
  subPath: string
  tenant: TenantContext
  /** `null` while `/authorize` is being initiated; populated on callback. */
  flow: FlowRecord | null
  /**
   * Shortcut to `flow?.methodState`, narrowed to this method's `S` generic.
   * `null` when there is no flow yet or no state has been written.
   */
  methodState: S | null
  /** Parsed cookies from the incoming `Request`. Read-only. */
  cookies: ReadonlyMap<string, string>
  /**
   * Framework-supplied dispatch data. Populated for the `GET /authorize`
   * initiation so the method can build an upstream redirect carrying the
   * framework-minted state envelope; `null` for callback handlers (the
   * framework has already verified `state` and the flow record by then,
   * and the relevant data is on `flow`).
   */
  dispatch: MethodDispatchData | null
  /**
   * Per-method-instance scratch storage scoped to
   * `(tenant.id, method.id)`. Survives across flows — distinct from
   * `methodState`, which is per-flow.
   *
   * Most methods do NOT need this. It exists for cross-flow
   * deduplication patterns such as SAML SP assertion-ID replay
   * protection.
   *
   * Backed by `SessionStore.{saveScratch,readScratch,deleteScratch}`
   * when those optional methods are implemented. Against adapters that
   * don't implement them, every call returns
   * `{ ok: false, error: unsupported }` — the method should surface a
   * `MethodResult.error` with a clear message, not silently degrade.
   */
  methodScratch: MethodScratch
}

/**
 * Caller-facing API for per-method-instance scratch. The framework
 * scopes user-supplied keys with a `(tenantId, methodId)` prefix before
 * delegating to `SessionStore` — adapters never see raw method keys.
 *
 * Values are UTF-8 strings; methods JSON-encode if they want to stash
 * objects. Keeping the port-level type narrow simplifies adapter
 * implementations (one TEXT column, one Dynamo `S` attribute, etc.).
 */
export type MethodScratch = {
  /**
   * Persist `value` under `key` with the given TTL. Overwrites prior
   * value for the same key. `ttlMs` must be positive.
   */
  put(key: string, value: string, ttlMs: number): Promise<Result<void>>
  /**
   * Read the value previously stored at `key`. Returns `unknown_state`
   * if the key is missing or expired (the underlying adapter MAY
   * lazily evict expired entries on read).
   */
  get(key: string): Promise<Result<string>>
  /** Idempotent. Resolves `ok` whether the key existed or not. */
  delete(key: string): Promise<Result<void>>
}

/** Framework-supplied data available to the method at `/authorize` time. */
export type MethodDispatchData = {
  /**
   * The MAC-signed state envelope the method must include in any upstream
   * redirect. Opaque to the method.
   */
  state: string
  /**
   * Fully qualified callback URL the upstream provider should redirect to.
   * Methods include this as `redirect_uri` (OAuth) or its equivalent.
   */
  callbackUrl: string
  /** The issuer URL of this IdP. Methods may include in upstream OIDC requests. */
  issuerUrl: string
}

/**
 * Discriminated union returned by a `MethodHandler`. The HTTP layer applies
 * the result: rendering the challenge response, kicking off token issuance
 * on success, or surfacing the error.
 */
export type MethodResult<P = unknown, S = unknown> =
  /**
   * Render UI / redirect to upstream / otherwise pause the flow waiting for
   * the user agent. `setCookies` is applied via the framework's serializer
   * (which enforces `Secure`, `SameSite`, `HttpOnly` defaults).
   * `saveMethodState` is merged into `FlowRecord.methodState` and persisted
   * **before** the response is sent — the user agent never sees the
   * upstream redirect until the upstream verifier / nonce / state is
   * durably saved.
   */
  | {
      kind: "challenge"
      /** Body + non-policy headers. Policy-sensitive headers are stripped. */
      response: Response
      setCookies?: SetCookie[]
      saveMethodState?: S
      /** Serialized into a `Cache-Control` header by the framework. */
      cache?: CachePolicy
    }
  /**
   * Authentication succeeded. The HTTP layer hands `providerSubject` +
   * `properties` to the user's `IdPOptions.success` callback to mint the
   * final `SubjectClaim`. Methods never construct the final subject.
   */
  | {
      kind: "success"
      /** Upstream system's stable identifier for the authenticated principal. */
      providerSubject: string
      properties: P
      setCookies?: SetCookie[]
    }
  /** User refused / failed auth in a non-error way (e.g. consent declined). */
  | { kind: "denied"; reason: string; setCookies?: SetCookie[] }
  /** Method hit an error. The HTTP layer maps to a standards-compliant response. */
  | { kind: "error"; error: AuthError }

/**
 * Cache policy for `MethodResult.challenge`. Methods do **not** set
 * `Cache-Control` directly — the framework strips that header from any
 * method-returned `Response`. Opt in to caching via this typed field; the
 * framework serializes it.
 */
export type CachePolicy = {
  /** Seconds. `0` ≡ `no-store`. Default for auth UI. */
  maxAge?: number
  /** Shared (CDN) cache TTL. */
  sMaxAge?: number
  /** Adds `Cache-Control: private`. */
  isPrivate?: boolean
  /** For static assets only. */
  immutable?: boolean
}

/**
 * Cookie instruction returned from a method, applied by the framework's
 * cookie serializer. Defaults enforced: `Secure` in production, `SameSite`
 * defaults to `Lax`, `HttpOnly` defaults to true for any cookie name in the
 * framework's reserved namespace (`auth.*` / `idp.*`).
 */
export type SetCookie = {
  name: string
  /** `null` clears the cookie (`Max-Age=0`). */
  value: string | null
  maxAge?: number
  path?: string
  domain?: string
  httpOnly?: boolean
  secure?: boolean
  sameSite?: "lax" | "strict" | "none"
}

/**
 * Token-exchange function for methods that participate in `/token`
 * (currently just `m2m`). Returns the same `P` properties shape as a
 * `MethodResult.success`.
 */
export type ClientFn<P> = (input: {
  clientID: string
  clientSecret: string
  params: Record<string, string>
}) => Promise<Result<P, AuthError>>

/**
 * Factory that turns a tenant's per-method config into an `AuthMethod`.
 *
 * The factory owns config validation. The framework validates
 * `MethodConfig.config` against `configSchema` before calling `build`;
 * methods never observe `Record<string, unknown>` at runtime.
 *
 * `build` may be async (e.g. to fetch an OIDC discovery doc / JWKS). The
 * result is cached per `(tenantId, MethodConfig.id)` — TTL matches the
 * `ConfigStore` cache TTL; invalidation fires when tenant config changes.
 *
 * The framework verifies the returned `AuthMethod.id` and `AuthMethod.kind`
 * match the `input.id` / `input.kind` passed into `build`. Mismatch fails
 * the load with audit `factory_id_mismatch`.
 */
// `AnyAuthMethodFactory` is the variance-permissive form used by
// `IdPOptions.methods` and `MethodCache.factories`. Each entry in such a
// map may be a `AuthMethodFactory<P, S, Cfg>` with concrete generics —
// the `any` defaults keep the map type assignable without losing strict
// typing inside individual factories.
export type AnyAuthMethodFactory = AuthMethodFactory<
  any, // P — properties emitted to success callback
  any, // S — method-private state
  any // Cfg — tenant-supplied config (validated by configSchema)
>

export type AuthMethodFactory<P = unknown, S = unknown, Cfg = unknown> = {
  /** Matches `MethodConfig.kind`. Multiple `MethodConfig` rows may share the same `kind`. */
  kind: string

  /**
   * Standard Schema for the tenant-supplied config blob. The framework
   * runs this after `ConfigStore` returns a tenant's `MethodConfig.config`
   * and rejects loads that don't validate (audit + log). The validated
   * value is threaded into `build`.
   *
   * Any validation library implementing [Standard Schema v1] satisfies
   * this contract — Zod 3.24+, Valibot 1.0+, Arktype 2.0+, Effect Schema,
   * etc. This decouples the library from any one validator's version
   * choices.
   *
   * [Standard Schema v1]: https://github.com/standard-schema/standard-schema
   */
  configSchema: v1.StandardSchema<unknown, Cfg>

  /**
   * Build a concrete `AuthMethod` from validated config plus the binding
   * context. The factory **must** set `AuthMethod.id` to `input.id` and
   * `AuthMethod.kind` to `input.kind` — the framework verifies and audits
   * on mismatch (`factory_id_mismatch`).
   */
  build: (input: {
    /** `MethodConfig.id` — tenant-local instance id, becomes `AuthMethod.id`. */
    id: string
    /** `MethodConfig.kind` — factory id, becomes `AuthMethod.kind`. */
    kind: string
    tenantId: TenantId
    /** Validated against `configSchema`. */
    config: Cfg
  }) => Promise<AuthMethod<P, S>>
}
