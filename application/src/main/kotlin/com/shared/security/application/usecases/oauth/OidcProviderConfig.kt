package com.shared.security.application.usecases.oauth

/**
 * Static deployment-derived configuration for the OIDC discovery document.
 *
 * The [issuer] is the externally-reachable base URL of the provider (the `security-ops.*`
 * hostname per the production topology). Every advertised endpoint is derived from it. The
 * [jwksPath] is fixed to the security-service's existing JWKS route so discovery's `jwks_uri`
 * points at the **one** JWKS document (proposal R-10) — it is not independently configurable,
 * to make a second JWKS source impossible to introduce by config.
 */
data class OidcProviderConfig(
    val issuer: String,
) {
    init {
        require(issuer.isNotBlank()) { "OIDC issuer must not be blank" }
        require(!issuer.endsWith("/")) { "OIDC issuer must not have a trailing slash: '$issuer'" }
    }

    val authorizationEndpoint: String get() = "$issuer$AUTHORIZATION_PATH"
    val tokenEndpoint: String get() = "$issuer$TOKEN_PATH"
    val userinfoEndpoint: String get() = "$issuer$USERINFO_PATH"

    /** Points at the existing `GET /v1/jwks` — one JWKS, one signing-key lifecycle (R-10). */
    val jwksUri: String get() = "$issuer$JWKS_PATH"

    companion object {
        const val DISCOVERY_PATH = "/.well-known/openid-configuration"
        const val AUTHORIZATION_PATH = "/authorize"
        const val TOKEN_PATH = "/token"
        const val USERINFO_PATH = "/userinfo"
        const val JWKS_PATH = "/v1/jwks"
    }
}
