/**
 * Public surface for the built-in server-rendered UI helpers.
 *
 * Hosts who want their own UI typically don't import from here at all —
 * they intercept at the host application layer. Hosts that want to keep
 * the defaults but tweak around the edges (e.g. supply a custom picker
 * while keeping the default credential forms) can pull renderForm /
 * renderPicker from here.
 */
export { renderForm, escapeHtml, htmlPage, BASE_STYLES } from "./forms"
export type { FormField } from "./forms"

export { renderPicker, buildMethodLink } from "./picker"
export type { PickerMethod, PickerContext } from "./picker"
