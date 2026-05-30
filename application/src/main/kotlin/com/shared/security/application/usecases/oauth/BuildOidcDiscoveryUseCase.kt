package com.shared.security.application.usecases.oauth

import com.shared.security.domain.oauth.OAuthClientAuthMethod
import com.shared.security.domain.oauth.OAuthGrantType
import com.shared.security.domain.oauth.OAuthScope

/**
 * Builds the metadata that the OIDC discovery document (`/.well-known/openid-configuration`)
 * advertises (proposal §4.3). Returns a plain [OidcDiscoveryMetadata] value; the `http-oauth`
 * adapter maps it onto the wire DTO in `contracts/oauth-oidc`, keeping the application layer
 * free of any wire/serialization type.
 *
 * The supported-feature lists describe the v1 *target* surface (proposal §4.2) so the document
 * is stable across the phased rollout; the actual `/token` + `/authorize` handlers that satisfy
 * them land in later phases. Signing alg is ES256-only (proposal C-1) — fixed in the DTO
 * default, never derived from config.
 */
class BuildOidcDiscoveryUseCase(
    private val config: OidcProviderConfig,
) {
    fun build(): OidcDiscoveryMetadata =
        OidcDiscoveryMetadata(
            issuer = config.issuer,
            authorizationEndpoint = config.authorizationEndpoint,
            tokenEndpoint = config.tokenEndpoint,
            userinfoEndpoint = config.userinfoEndpoint,
            jwksUri = config.jwksUri,
            scopesSupported = SUPPORTED_SCOPES,
            responseTypesSupported = SUPPORTED_RESPONSE_TYPES,
            grantTypesSupported = OAuthGrantType.entries.map { it.wireValue },
            tokenEndpointAuthMethodsSupported = OAuthClientAuthMethod.entries.map { it.wireValue },
            claimsSupported = SUPPORTED_CLAIMS,
        )

    private companion object {
        // openid is mandatory for OIDC; the rest are placeholders for the v1 claim surface
        // (proposal §4.3 id_token claims). Extended as later phases add real scope policy.
        private val SUPPORTED_SCOPES = listOf(OAuthScope.OPENID.value, "profile", "email")

        // Auth-Code only (PKCE). No implicit grant (proposal §4.2).
        private val SUPPORTED_RESPONSE_TYPES = listOf("code")

        // id_token claims the OP intends to assert (proposal §4.3): standard OIDC + amr/acr +
        // the existing role claim.
        private val SUPPORTED_CLAIMS =
            listOf("iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "amr", "acr", "role")
    }
}

/**
 * Plain (framework-free) carrier for the discovery metadata. The `http-oauth` adapter maps
 * this onto `contracts/oauth-oidc`'s `OidcDiscoveryDocument` wire DTO.
 */
data class OidcDiscoveryMetadata(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userinfoEndpoint: String,
    val jwksUri: String,
    val scopesSupported: List<String>,
    val responseTypesSupported: List<String>,
    val grantTypesSupported: List<String>,
    val tokenEndpointAuthMethodsSupported: List<String>,
    val claimsSupported: List<String>,
)
