/**
 * Minimal `D1Database` shim backed by `bun:sqlite`. Used by the D1 adapter
 * conformance test (`test/adapters/d1.test.ts`) so we don't need miniflare
 * or a real Worker runtime to exercise the SQL.
 *
 * The shim implements just enough of the D1 API surface that our adapter
 * uses: `prepare(sql).bind(...).first/all/run/raw`. The Sessions API
 * (`withSession`) is intentionally omitted — the adapter feature-detects it
 * and falls back to plain `prepare`, which is exactly the code path
 * production runtimes without Sessions exercise.
 */
import { Database, Statement } from "bun:sqlite"

import type {
  D1Database,
  D1PreparedStatement,
  D1Result,
} from "@cloudflare/workers-types"

export function createD1Shim(): D1Database {
  const db = new Database(":memory:")
  return new BunD1Database(db) as unknown as D1Database
}

class BunD1Database {
  constructor(public readonly db: Database) {}
  prepare(query: string): D1PreparedStatement {
    return new BunD1PreparedStatement(
      this.db,
      query,
      [],
    ) as unknown as D1PreparedStatement
  }
  async batch<T = unknown>(
    statements: D1PreparedStatement[],
  ): Promise<D1Result<T>[]> {
    const out: D1Result<T>[] = []
    for (const stmt of statements) {
      out.push(await (stmt as unknown as BunD1PreparedStatement).run<T>())
    }
    return out
  }
  async exec(query: string): Promise<{ count: number; duration: number }> {
    this.db.exec(query)
    return { count: 0, duration: 0 }
  }
  async dump(): Promise<ArrayBuffer> {
    return new ArrayBuffer(0)
  }
}

class BunD1PreparedStatement {
  #stmt: Statement | null = null
  constructor(
    private readonly db: Database,
    private readonly query: string,
    private bindings: unknown[],
  ) {}
  bind(...values: unknown[]): D1PreparedStatement {
    return new BunD1PreparedStatement(
      this.db,
      this.query,
      normalizeBindings(values),
    ) as unknown as D1PreparedStatement
  }
  #ensureStmt(): Statement {
    if (!this.#stmt) this.#stmt = this.db.prepare(this.query)
    return this.#stmt
  }
  async first<T = unknown>(colName?: string): Promise<T | null> {
    const stmt = this.#ensureStmt()
    const row = stmt.get(...(this.bindings as never[])) as Record<
      string,
      unknown
    > | null
    if (!row) return null
    if (colName) return (row[colName] as T) ?? null
    return row as unknown as T
  }
  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const stmt = this.#ensureStmt()
    // `all` for SELECT / RETURNING; bun:sqlite's `all` also handles INSERT etc.
    const rows = stmt.all(...(this.bindings as never[])) as unknown as T[]
    return {
      success: true,
      results: rows,
      meta: {} as never,
    }
  }
  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.run<T>()
  }
  async raw<T = unknown[]>(opts?: {
    columnNames?: boolean
  }): Promise<T[] | [string[], ...T[]]> {
    const stmt = this.#ensureStmt()
    const rows = stmt.values(...(this.bindings as never[])) as T[]
    if (opts?.columnNames) {
      // bun:sqlite doesn't expose column names from `values()`; punt by
      // reading from the first row of `all()` if needed. Our adapter
      // doesn't call this, so a stub is fine.
      const all = stmt.all(...(this.bindings as never[])) as Array<
        Record<string, unknown>
      >
      const cols = all[0] ? Object.keys(all[0]) : []
      return [cols, ...rows] as [string[], ...T[]]
    }
    return rows
  }
}

/**
 * Normalize JS-land bindings to forms bun:sqlite accepts:
 *  - Buffer / Uint8Array — passed through
 *  - undefined → null
 *  - booleans → 1 / 0 (SQLite has no native bool)
 */
function normalizeBindings(values: unknown[]): unknown[] {
  return values.map((v) => {
    if (v === undefined) return null
    if (typeof v === "boolean") return v ? 1 : 0
    return v
  })
}
