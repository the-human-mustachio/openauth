/**
 * Source-level guard: no file outside `src/methods/saml-sp/` may
 * import from the SAML SP subpath or from its (Node-only) third-party
 * dependencies. This is the load-bearing invariant for keeping the
 * root entry edge-clean — Workers / browsers can keep importing
 * `@_mustachio/openauth` without ever pulling in `@node-saml/*`,
 * `xml-crypto`, or `@xmldom/*`.
 *
 * Companion to `saml-sp-no-thirdparty-leaks.test.ts` (which guards the
 * type surface). This file scans the actual import graph at the source
 * level, so a regression — say, a quick "I'll just re-export
 * `samlSpFactory` from `src/index.ts`" — fails CI immediately.
 *
 * To extend: add a new entry to `FORBIDDEN_PATTERNS`.
 */
import { Glob } from "bun"
import { test, expect } from "bun:test"
import { readFile } from "node:fs/promises"
import { join, relative } from "node:path"

const PROJECT_ROOT = join(import.meta.dir, "..", "..")
const SRC_ROOT = join(PROJECT_ROOT, "src")
const SAML_DIR = join(SRC_ROOT, "methods", "saml-sp")

/**
 * Each pattern is a substring (case-sensitive) that, if found inside an
 * import / re-export specifier outside `src/methods/saml-sp/`, fails
 * the test.
 */
const FORBIDDEN_PATTERNS: ReadonlyArray<{
  pattern: string
  reason: string
}> = [
  {
    pattern: "@node-saml/",
    reason: "@node-saml/* is a Node-only dep — must stay isolated to src/methods/saml-sp/",
  },
  {
    pattern: "xml-crypto",
    reason: "xml-crypto requires node:crypto — must stay isolated to src/methods/saml-sp/",
  },
  {
    pattern: "@xmldom/",
    reason: "@xmldom/* is a Node-targeted XML parser — must stay isolated to src/methods/saml-sp/",
  },
  {
    pattern: "xml-encryption",
    reason: "xml-encryption is Node-only — must stay isolated to src/methods/saml-sp/",
  },
  {
    pattern: "xml2js",
    reason: "xml2js is Node-only — must stay isolated to src/methods/saml-sp/",
  },
  {
    pattern: "xmlbuilder",
    reason: "xmlbuilder is Node-only — must stay isolated to src/methods/saml-sp/",
  },
  {
    pattern: "methods/saml-sp",
    reason: "SAML SP module must not be imported from anywhere else — keeps the root entry edge-clean",
  },
]

const IMPORT_LIKE_RE =
  /(?:from|import)\s*(?:\(\s*)?(?:"([^"]+)"|'([^']+)')/g

async function scanFile(absPath: string): Promise<string[]> {
  const text = await readFile(absPath, "utf8")
  const offenders: string[] = []
  for (const match of text.matchAll(IMPORT_LIKE_RE)) {
    const specifier = match[1] ?? match[2]
    if (!specifier) continue
    for (const { pattern, reason } of FORBIDDEN_PATTERNS) {
      if (specifier.includes(pattern)) {
        offenders.push(
          `${relative(PROJECT_ROOT, absPath)}: imports "${specifier}" — ${reason}`,
        )
      }
    }
  }
  return offenders
}

test("no source file outside src/methods/saml-sp/ imports SAML or its Node-only deps", async () => {
  const glob = new Glob("**/*.{ts,tsx}")
  const offenders: string[] = []
  for await (const rel of glob.scan({ cwd: SRC_ROOT })) {
    const abs = join(SRC_ROOT, rel)
    if (abs.startsWith(SAML_DIR + "/") || abs === SAML_DIR) continue
    const found = await scanFile(abs)
    offenders.push(...found)
  }
  if (offenders.length > 0) {
    // Surfacing every violation up front beats a one-by-one debug loop.
    throw new Error(
      `SAML SP isolation violated. The following files reach into the SAML SP module or its Node-only deps:\n  - ${offenders.join("\n  - ")}`,
    )
  }
  expect(offenders.length).toBe(0)
})
