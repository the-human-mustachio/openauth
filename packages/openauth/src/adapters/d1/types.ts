/**
 * D1 type extensions.
 *
 * `@cloudflare/workers-types` < 2024-12 does not yet expose the D1 Sessions
 * API on its `D1Database` class. We declare the augmentation locally and
 * feature-detect at runtime: if `db.withSession` is a function the adapter
 * uses it for read-after-write consistency on the security-critical paths;
 * otherwise it falls back to plain `prepare`. This keeps the adapter
 * type-safe today and forward-compatible when the workers-types release
 * catches up.
 */
import type { D1Database, D1PreparedStatement, D1Result } from "@cloudflare/workers-types"

/**
 * D1 Sessions API constraints. Documented at
 * <https://developers.cloudflare.com/d1/best-practices/read-replication/>.
 *  - `"first-primary"` — pin the session to the primary node. All reads see
 *    the latest write. Used for security-critical paths.
 *  - `"first-unconstrained"` — pin to whichever node responds first. Lower
 *    latency, eventual consistency. Used for JWKS / config reads.
 */
export type D1SessionConstraint = "first-primary" | "first-unconstrained"

/** A session bookmark — opaque token returned by `getBookmark()`. */
export type D1SessionBookmark = string

/** Minimal shape we use from `D1DatabaseSession`. */
export type D1DatabaseSession = {
  prepare(query: string): D1PreparedStatement
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>
  getBookmark(): D1SessionBookmark | null
}

/**
 * `D1Database` with the Sessions API. Use this type at the adapter boundary;
 * the runtime feature-detects `withSession` so consumers can still pass a
 * plain `D1Database` if Sessions is unavailable in their environment.
 */
export type D1DatabaseWithSessions = D1Database & {
  withSession(
    constraintOrBookmark?: D1SessionConstraint | D1SessionBookmark,
  ): D1DatabaseSession
}

/**
 * Either a real D1Database or our test shim. Feature detection happens at
 * call time so the adapter still works against both.
 */
export type AnyD1Database = D1Database | D1DatabaseWithSessions
