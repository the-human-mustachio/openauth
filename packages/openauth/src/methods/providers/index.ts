/**
 * Pre-configured OAuth/OIDC provider factories.
 *
 * Each factory is a thin wrapper over `buildOauth2Method` or
 * `buildOidcMethod` that bakes in endpoint URLs and provider quirks.
 * Tenants supply credentials via `MethodConfig.config`; the generic
 * methods own the rest.
 */
export { googleFactory } from "./google"
export { githubFactory } from "./github"
export { appleFactory } from "./apple"
export { microsoftFactory } from "./microsoft"
export { discordFactory } from "./discord"
export { facebookFactory } from "./facebook"
export { linkedinFactory } from "./linkedin"
export { slackFactory } from "./slack"
export { spotifyFactory } from "./spotify"
export { twitchFactory } from "./twitch"
export { xFactory } from "./x"
export { yahooFactory } from "./yahoo"
export { jumpcloudFactory } from "./jumpcloud"
export { keycloakFactory } from "./keycloak"
export { cognitoFactory } from "./cognito"
