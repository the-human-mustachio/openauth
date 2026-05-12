/**
 * Parameterized port-conformance suite — re-export.
 *
 * Each adapter's test file imports the `describe*Store` factories from here
 * and supplies adapter-specific `makeStore` callbacks. An adapter that fails
 * any case is **not certified** for production per `ports/CONSISTENCY.md`.
 */
export { describeTokenStore, type TokenStoreSuiteOptions } from "./token-store"
export {
  describeSessionStore,
  type SessionStoreSuiteOptions,
} from "./session-store"
export { describeKeyStore, type KeyStoreSuiteOptions } from "./key-store"
export {
  describeConfigStore,
  type ConfigStoreSuiteOptions,
} from "./config-store"
export {
  describeMethodStore,
  type MethodStoreSuiteOptions,
} from "./method-store"
export { describeAuditLog, type AuditLogSuiteOptions } from "./audit-log"
export {
  describePasskeyCredentialStore,
  type PasskeyCredentialStoreSuiteOptions,
} from "./passkey-credential-store"

export {
  fixtureTenantId,
  makeCodePayload,
  makeFlow,
  makeRefreshPayload,
  makeTenantConfig,
  testClock,
  uniqueSuffix,
  type TestClock,
} from "./fixtures"
