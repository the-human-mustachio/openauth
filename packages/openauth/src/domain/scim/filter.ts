/**
 * SCIM filter parsing — the deliberately narrow subset (`SCIM-AD3`).
 *
 * RFC 7644 §3.4.2.2 defines a full expression language: grouping,
 * precedence, `co`/`sw`/`ew`/`pr`/`gt`/`ge`/`lt`/`le`, complex attribute
 * paths, `not`, and arbitrary nesting. Okta and Entra emit a sliver of
 * it — overwhelmingly `userName eq "…"` for the existence check before a
 * create.
 *
 * Implementing the rest would mean either a large parser plus a query
 * interface no host could reasonably satisfy, or quietly returning wrong
 * results. We support the observed subset and reject everything else
 * with a message naming what works, so a gap is visible on day one
 * rather than becoming silent provisioning drift.
 *
 * Supported:
 *
 *     userName eq "alice@corp.example"
 *     externalId eq "00u1abc"
 *     id eq "usr_123"
 *     active eq true
 *     emails[type eq "work"].value eq "a@b.com"   (Entra's shape)
 *     emails.value eq "a@b.com"
 *     <term> and <term>                           (two terms, no nesting)
 *
 * Pure: no I/O, no port access. Returns a `Result` so the caller renders
 * the SCIM error envelope.
 */
import type { ScimFilter, ScimFilterAttribute } from "../../types/scim"
import { err, ok, type Result } from "../../types/result"

/** What we tell a client when their filter is outside the subset. */
export const SUPPORTED_FILTER_HELP =
  'supported filters are: userName eq "…", externalId eq "…", id eq "…", ' +
  'active eq true|false, emails[type eq "…"].value eq "…", and two of ' +
  'those joined by "and"'

export type ScimFilterError = { detail: string }

const ATTRIBUTES: Record<string, ScimFilterAttribute> = {
  id: "id",
  username: "userName",
  externalid: "externalId",
  active: "active",
  "emails.value": "emails.value",
  displayname: "displayName",
}

/**
 * Which attributes each resource type may be filtered on. Filtering a
 * Group by `userName` is nonsense, and answering it with an empty list
 * rather than a 400 would look like "no such group" — a wrong answer
 * dressed as a valid one.
 */
export const USER_FILTER_ATTRIBUTES: ReadonlySet<ScimFilterAttribute> =
  new Set(["id", "userName", "externalId", "active", "emails.value"])

export const GROUP_FILTER_ATTRIBUTES: ReadonlySet<ScimFilterAttribute> =
  new Set(["id", "displayName", "externalId"])

/**
 * Normalize the complex multi-valued path Entra emits.
 *
 * `emails[type eq "work"].value` means "the value of the work email".
 * We collapse the qualifier: the host matches on any email value. That
 * is a deliberate simplification — a user with the same address under
 * two `type`s is the same person, and hosts that model emails as a flat
 * list (most of them) cannot honour the qualifier anyway.
 */
function normalizeComplexPath(raw: string): string {
  const m = /^([A-Za-z]+)\[[^\]]*\]\.([A-Za-z]+)$/.exec(raw.trim())
  if (!m) return raw.trim()
  return `${m[1]}.${m[2]}`
}

/**
 * Locate the comparison operator at bracket depth 0, outside quotes.
 *
 * A naive regex splits `emails[type eq "work"].value eq "a@b.c"` on the
 * *inner* `eq` and mis-reads the attribute as `emails[type`. The
 * qualifier of a complex attribute contains its own operator, so the
 * scan has to respect brackets.
 */
function findOperator(
  term: string,
): { attr: string; op: string; value: string } | null {
  let depth = 0
  let inQuotes = false
  for (let i = 0; i < term.length; i++) {
    const ch = term[i]
    if (ch === '"' && term[i - 1] !== "\\") {
      inQuotes = !inQuotes
      continue
    }
    if (inQuotes) continue
    if (ch === "[") depth++
    else if (ch === "]") depth--
    else if (depth === 0 && ch === " ") {
      const m = /^\s+([A-Za-z]{2,3})(?:\s+|$)/.exec(term.slice(i))
      if (m) {
        return {
          attr: term.slice(0, i),
          op: m[1] as string,
          value: term.slice(i + (m[0] as string).length),
        }
      }
    }
  }
  return null
}

/** Parse one `<attr> eq <value>` term. */
function parseTerm(
  raw: string,
  allowed: ReadonlySet<ScimFilterAttribute>,
): Result<ScimFilter, ScimFilterError> {
  const term = raw.trim()

  const found = findOperator(term)
  if (!found) {
    return err({
      detail: `could not parse filter term "${term}". ${SUPPORTED_FILTER_HELP}`,
    })
  }
  const { attr: rawAttr, op: rawOp, value: rawValue } = found

  if (rawOp.toLowerCase() !== "eq") {
    return err({
      detail:
        `operator "${rawOp}" is not supported; only "eq" is. ` +
        SUPPORTED_FILTER_HELP,
    })
  }

  const attrKey = normalizeComplexPath(rawAttr).toLowerCase()
  const attribute = ATTRIBUTES[attrKey]
  if (!attribute || !allowed.has(attribute)) {
    return err({
      detail:
        `attribute "${rawAttr.trim()}" is not filterable. ` +
        SUPPORTED_FILTER_HELP,
    })
  }

  const value = rawValue.trim()

  if (attribute === "active") {
    const lowered = value.toLowerCase()
    if (lowered !== "true" && lowered !== "false") {
      return err({
        detail: `"active" must be compared to true or false, got ${value}`,
      })
    }
    return ok({ op: "eq", attribute, value: lowered === "true" })
  }

  // Every other supported attribute is a quoted string.
  if (value.length < 2 || !value.startsWith('"') || !value.endsWith('"')) {
    return err({
      detail: `value for "${attribute}" must be a quoted string, got ${value}`,
    })
  }
  const unquoted = value
    .slice(1, -1)
    // RFC 7644 uses JSON string escaping; only \" and \\ are plausible here.
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\")

  if (unquoted.length === 0) {
    return err({ detail: `value for "${attribute}" must not be empty` })
  }
  return ok({ op: "eq", attribute, value: unquoted })
}

/**
 * Parse a SCIM `filter` query parameter.
 *
 * Returns `ok(undefined)` for an absent or blank filter — an unfiltered
 * list is legal and is what Okta sends when importing all users.
 */
export function parseScimFilter(
  raw: string | null | undefined,
  allowed: ReadonlySet<ScimFilterAttribute> = USER_FILTER_ATTRIBUTES,
): Result<ScimFilter | undefined, ScimFilterError> {
  if (raw === null || raw === undefined || raw.trim().length === 0) {
    return ok(undefined)
  }
  const input = raw.trim()

  // Every structural check below runs against a *masked* copy in which
  // the contents of quoted literals are blanked out. Testing the raw
  // string rejected perfectly ordinary values — a group called
  // "Sales (EMEA)" looked like a grouped expression, and a user called
  // "jack or jill" looked like a disjunction. Both are common, and the
  // damage is worse than a bad error message: Okta reacts to a failed
  // existence lookup by creating a duplicate.
  const masked = maskQuoted(input)

  if (masked.includes("(") || masked.includes(")")) {
    return err({
      detail: `grouped expressions are not supported. ${SUPPORTED_FILTER_HELP}`,
    })
  }

  // Split on a top-level ` and `, ignoring one inside a quoted value or
  // inside a complex-attribute qualifier (`emails[type eq "work"]`).
  const parts = splitTopLevelAnd(input)

  if (parts.length > 2) {
    return err({
      detail:
        `at most two terms joined by "and" are supported. ` +
        SUPPORTED_FILTER_HELP,
    })
  }
  if (/\sor\s/i.test(masked)) {
    return err({
      detail: `"or" is not supported. ${SUPPORTED_FILTER_HELP}`,
    })
  }
  if (/(^|\s)not\s/i.test(masked)) {
    return err({
      detail: `"not" is not supported. ${SUPPORTED_FILTER_HELP}`,
    })
  }

  const first = parseTerm(parts[0] as string, allowed)
  if (!first.ok) return first
  if (parts.length === 1) return ok(first.value)

  const second = parseTerm(parts[1] as string, allowed)
  if (!second.ok) return second
  return ok({ op: "and", left: first.value, right: second.value })
}


/**
 * Replace the contents of every quoted literal with spaces, preserving
 * length and the quote characters themselves. Lets the structural checks
 * reason about filter *syntax* without tripping over filter *values*.
 */
function maskQuoted(input: string): string {
  let out = ""
  let inQuotes = false
  for (let i = 0; i < input.length; i++) {
    const ch = input[i] as string
    if (ch === '"' && input[i - 1] !== "\\") {
      inQuotes = !inQuotes
      out += ch
      continue
    }
    out += inQuotes ? " " : ch
  }
  return out
}

/**
 * Split on ` and ` at the top level only. Quoted strings and the
 * `[...]` qualifier of a complex attribute may both legitimately
 * contain the word, so a naive split corrupts them.
 */
function splitTopLevelAnd(input: string): string[] {
  const parts: string[] = []
  let depth = 0
  let inQuotes = false
  let start = 0

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]
    if (ch === '"' && input[i - 1] !== "\\") {
      inQuotes = !inQuotes
      continue
    }
    if (inQuotes) continue
    if (ch === "[") depth++
    else if (ch === "]") depth--
    else if (depth === 0 && (ch === "a" || ch === "A")) {
      // Match a standalone " and " (case-insensitive) at this position.
      const window = input.slice(i, i + 3)
      const before = input[i - 1]
      const after = input[i + 3]
      if (
        window.toLowerCase() === "and" &&
        (before === " " || before === undefined) &&
        (after === " " || after === undefined)
      ) {
        parts.push(input.slice(start, i))
        start = i + 3
        i += 2
      }
    }
  }
  parts.push(input.slice(start))
  return parts.map((p) => p.trim()).filter((p) => p.length > 0)
}
