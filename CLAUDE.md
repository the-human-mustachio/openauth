# Claude Code Guidelines

This file provides context for Claude Code when working on this project.

## Project Overview

OpenAuth is a standards-based auth provider for web apps, mobile apps, SPAs, APIs, and 3rd party clients. It's built on [Hono](https://hono.dev) and can run anywhere (Node.js, Bun, AWS Lambda, Cloudflare Workers).

## Project Structure

```
openauth/
├── packages/openauth/     # Main package
│   ├── src/               # Source code
│   │   ├── issuer.ts      # Main issuer implementation
│   │   ├── provider/      # Auth providers (GitHub, Google, Password, etc.)
│   │   ├── storage/       # Storage adapters (DynamoDB, Cloudflare KV, Memory)
│   │   └── ui/            # UI components
│   └── test/              # Tests
├── www/                   # Documentation website (Astro/Starlight)
├── examples/              # Example implementations
└── docs/                  # Internal documentation
```

## Development Commands

```bash
# Run tests
cd packages/openauth && bun test

# Build the package
cd packages/openauth && bun run build

# Build documentation site
cd www && bun run build
```

## Documentation

- [Release Process](docs/release-process.md) - How to create releases with changesets

## Key Files

- `packages/openauth/src/issuer.ts` - Main issuer implementation, creates the Hono app
- `packages/openauth/src/provider/provider.ts` - Provider interface definition
- `.github/workflows/release.yml` - Release automation workflow

## Testing

Tests use Bun's built-in test runner. Run from `packages/openauth/`:

```bash
bun test                    # Run all tests
bun test issuer            # Run specific test file
bun test dynamic-providers # Run dynamic providers tests
```

## Code Style

- TypeScript with strict mode
- Prettier for formatting (runs via GitHub Action)
- JSDoc comments are used for documentation generation

## Multi-tenant Features

The issuer supports multi-tenant configurations:

- `basePath` - Dynamic URL prefix for mounted issuers
- `cookies.path` - Cookie path configuration
- `context` - Extract custom request context available in providers and callbacks
- `tenantId` - Available via `/tenant/:tenantId/` routes

See `packages/openauth/src/issuer.ts` for implementation details.
