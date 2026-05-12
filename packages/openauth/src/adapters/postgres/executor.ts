/**
 * Thin SQL-executor interface the Postgres adapters depend on.
 *
 * Both the production `postgres` (porsager/postgres) driver and the embedded
 * `@electric-sql/pglite` test driver fit behind this shape. Adapters never
 * import either driver directly — users wire one of the `from*` helpers
 * below.
 */

/** One row of a SQL result, addressed by column name. */
export type Row = Record<string, unknown>

/**
 * Minimal Postgres-shaped executor. Positional `$1, $2` parameters; rows are
 * column-name keyed objects.
 */
export type PostgresExecutor = {
  query<T extends Row = Row>(
    sql: string,
    params?: ReadonlyArray<unknown>,
  ): Promise<{ rows: T[] }>
}

/**
 * Wrap a porsager/postgres `Sql` instance in the `PostgresExecutor` shape.
 * The adapter calls `sql.unsafe(text, params)` so positional binds work.
 *
 * @example
 *   import postgres from "postgres"
 *   import { fromPostgresJs, PostgresTokenStore } from "@_mustachio/openauth/adapters/postgres"
 *   const sql = postgres(process.env.DATABASE_URL!)
 *   const exec = fromPostgresJs(sql)
 *   const store = new PostgresTokenStore({ exec, keyStore })
 */
export function fromPostgresJs(sql: PostgresJsLike): PostgresExecutor {
  return {
    async query<T extends Row = Row>(
      text: string,
      params: ReadonlyArray<unknown> = [],
    ): Promise<{ rows: T[] }> {
      const result = await sql.unsafe(text, params as unknown[])
      // porsager/postgres returns an array-shaped result with row objects.
      return { rows: Array.from(result as unknown as Iterable<T>) }
    },
  }
}

/** Minimal shape we use from porsager/postgres — kept untyped to avoid a runtime import. */
export type PostgresJsLike = {
  unsafe: (text: string, params: unknown[]) => Promise<unknown>
}

/**
 * Wrap a PGlite instance in the `PostgresExecutor` shape. Used by the
 * port-conformance suite to run the Postgres adapters in-process without a
 * server.
 */
export function fromPGlite(db: PGliteLike): PostgresExecutor {
  return {
    async query<T extends Row = Row>(
      text: string,
      params: ReadonlyArray<unknown> = [],
    ): Promise<{ rows: T[] }> {
      const result = await db.query<T>(text, params as unknown[])
      return { rows: result.rows }
    },
  }
}

/** Minimal shape we use from @electric-sql/pglite. */
export type PGliteLike = {
  query: <T extends Row = Row>(
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: T[] }>
}
