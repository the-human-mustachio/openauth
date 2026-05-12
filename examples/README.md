# Examples

| Example | What it shows |
|---|---|
| [`embed-postgres/`](embed-postgres/) | Minimum-viable host embedding — Node/Bun + Postgres adapter set + password + Google sign-in. |

If you want a different deployment target (Cloudflare Workers,
DynamoDB / Lambda, etc.), swap the `adapters/postgres` imports in
`embed-postgres/index.ts` for the equivalent backend — see
INTEGRATION.md § 4 for the full coverage matrix.
