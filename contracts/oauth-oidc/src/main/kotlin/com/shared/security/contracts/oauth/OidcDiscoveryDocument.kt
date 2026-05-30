package com.shared.security.contracts.oauth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OpenID Connect Discovery 1.0 metadata document, served at
 * `GET /.well-known/openid-configuration`.
 *
 * **One JWKS (proposal R-10).** [jwksUri] points at the security-service's existing
 * `GET /v1/jwks` endpoint — there is exactly one JWKS document and one signing-key
 * lifecycle. Discovery is metadata only; it never returns key material itself.
 *
 * **ES256 only (proposal C-1).** [idTokenSigningAlgValuesSupported] advertises `ES256`
 * exclusively. The OP must never advertise HS256/RS256/EdDSA/`none`.
 *
 * For the provider skeleton the supported-grant / response-type / scope lists describe the
 * v1 target surface (proposal §4.2) so the document is stable; the actual `/token` and
 * `/authorize` handlers that satisfy them land in later phases. The field names use the
 * exact OIDC-registered snake_case spellings (relying parties match on them).
 */
@Serializable
data class OidcDiscoveryDocument(
    val issuer: String,
    @SerialName("authorization_endpoint")
    val authorizationEndpoint: String,
    @SerialName("token_endpoint")
    val tokenEndpoint: String,
    @SerialName("userinfo_endpoint")
    val userinfoEndpoint: String,
    @SerialName("jwks_uri")
    val jwksUri: String,
    @SerialName("scopes_supported")
    val scopesSupported: List<String>,
    @SerialName("response_types_supported")
    val responseTypesSupported: List<String>,
    @SerialName("grant_types_supported")
    val grantTypesSupported: List<String>,
    @SerialName("subject_types_supported")
    val subjectTypesSupported: List<String> = listOf("public"),
    @SerialName("id_token_signing_alg_values_supported")
    val idTokenSigningAlgValuesSupported: List<String> = listOf("ES256"),
    @SerialName("token_endpoint_auth_methods_supported")
    val tokenEndpointAuthMethodsSupported: List<String>,
    @SerialName("code_challenge_methods_supported")
    val codeChallengeMethodsSupported: List<String> = listOf("S256"),
    @SerialName("claims_supported")
    val claimsSupported: List<String>,
)
