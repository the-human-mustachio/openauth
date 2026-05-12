/**
 * Public-surface types for the default provider picker and any
 * host-supplied override (`IdPOptions.renderPicker`). Kept under `types/`
 * — separate from `ui/picker.ts` which holds the default renderer — so
 * the public-API layer doesn't depend on the UI implementation file.
 */

/** Minimal shape of a method as seen by the picker. */
export type PickerMethod = {
  /** Tenant-local id (e.g. "google-workspace"). Goes into method_id. */
  id: string
  /** Factory kind (e.g. "google"). Identifies the provider family. */
  kind: string
  /** "redirect" for upstream OAuth/OIDC, "credential" for password/code/passkey. */
  type: string
  /** Optional human-readable label provided by tenant config. */
  displayName?: string
}

/** Query params propagated into each picker option's link. */
export type PickerContext = {
  clientId: string
  redirectUri: string
  state?: string | null
  scope?: string | null
  nonce?: string | null
  codeChallenge?: string | null
  codeChallengeMethod?: string | null
  audience?: string | null
  prompt?: string | null
  uiLocales?: string | null
}
