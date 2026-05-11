/**
 * Sessions-API helper. Wraps a `D1Database` in a session pinned to the
 * primary node for read-after-write consistency on security-critical paths.
 *
 * If the bundled `D1Database` lacks `withSession` (older runtime), the
 * helper returns the plain `db` and the caller pays no Sessions-API cost
 * (and gets eventual-consistency reads — documented in the adapter's
 * top-level JSDoc).
 */
import type { AnyD1Database, D1DatabaseSession, D1DatabaseWithSessions } from "./types"

export function isSessionsCapable(db: AnyD1Database): db is D1DatabaseWithSessions {
  return typeof (db as D1DatabaseWithSessions).withSession === "function"
}

/**
 * Open a Sessions-API session pinned to the primary node. All `prepare` calls
 * inside the session see the latest writes; bookmarks may be threaded across
 * requests by the caller if needed.
 */
export function primarySession(db: AnyD1Database): D1DatabaseSession {
  if (isSessionsCapable(db)) {
    return db.withSession("first-primary")
  }
  // Test shim / older runtime — fall back to the database itself, which
  // exposes the same `prepare` / `batch` shape. `getBookmark` returns null.
  return {
    prepare: (q) => db.prepare(q),
    batch: (s) => db.batch(s),
    getBookmark: () => null,
  }
}
