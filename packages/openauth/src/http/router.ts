/**
 * Top-level Hono router for the IdP HTTP surface.
 *
 * Routes (Phase 3):
 *   GET  /authorize                                    — start OAuth flow
 *   POST /token                                         — exchange code / refresh
 *   GET  /userinfo, POST /userinfo                      — OIDC claims
 *   GET  /cb/:methodId{.*}                              — upstream callback
 *   GET  /.well-known/openid-configuration              — discovery
 *   GET  /.well-known/oauth-authorization-server        — discovery (alias)
 *   GET  /.well-known/jwks.json                         — JWKS
 *   POST /revoke                                        — RFC 7009
 *   POST /introspect                                    — RFC 7662
 *
 * Hono is imported **only** from this directory. `domain/`, `methods/`,
 * `types/`, `ports/`, and `adapters/` remain framework-agnostic.
 */
import { Hono } from "hono"

import { makeAuthorizeHandler } from "./handlers/authorize"
import { makeCallbackHandler } from "./handlers/callback"
import { makeEndSessionHandler } from "./handlers/end-session"
import { makeDiscoveryHandler, makeJwksHandler } from "./handlers/metadata"
import { makeMethodRouteHandler } from "./handlers/method-route"
import { makeIntrospectHandler, makeRevokeHandler } from "./handlers/revocation"
import { makeTokenHandler } from "./handlers/token"
import { makeUserinfoHandler } from "./handlers/userinfo"
import { errorMiddleware } from "./middleware/error"
import { bootstrapMiddleware, tenantMiddleware } from "./middleware/tenant"
import type { HttpDeps, HttpEnv } from "./context"

export function buildRouter(deps: HttpDeps): Hono<HttpEnv> {
  const app = new Hono<HttpEnv>()

  app.use("*", errorMiddleware(deps))
  app.use("*", bootstrapMiddleware(deps))

  // Public metadata — no tenant middleware required.
  app.get("/.well-known/openid-configuration", makeDiscoveryHandler(deps))
  app.get("/.well-known/oauth-authorization-server", makeDiscoveryHandler(deps))
  app.get("/.well-known/jwks.json", makeJwksHandler(deps))

  // Tenant-scoped endpoints.
  app.use("/authorize", tenantMiddleware(deps))
  app.get("/authorize", makeAuthorizeHandler(deps))

  app.use("/cb/*", tenantMiddleware(deps))
  app.get("/cb/*", makeCallbackHandler(deps))
  // Apple `response_mode=form_post` and similar POST-binding callbacks.
  app.post("/cb/*", makeCallbackHandler(deps))

  // Credential-flow method routes — POST and GET allowed.
  app.use("/m/*", tenantMiddleware(deps))
  app.all("/m/*", makeMethodRouteHandler(deps))

  // Token endpoint — tenant resolved from auth-code payload, not middleware.
  app.post("/token", makeTokenHandler(deps))

  // Userinfo — bearer token carries tenant claim (`tid`).
  app.get("/userinfo", makeUserinfoHandler(deps))
  app.post("/userinfo", makeUserinfoHandler(deps))

  app.post("/revoke", makeRevokeHandler(deps))
  app.post("/introspect", makeIntrospectHandler(deps))

  // OIDC RP-Initiated Logout 1.0. Tenant resolved via the standard
  // middleware — same partitioning rules as `/authorize`.
  app.use("/end_session", tenantMiddleware(deps))
  app.get("/end_session", makeEndSessionHandler(deps))
  app.post("/end_session", makeEndSessionHandler(deps))

  return app
}
