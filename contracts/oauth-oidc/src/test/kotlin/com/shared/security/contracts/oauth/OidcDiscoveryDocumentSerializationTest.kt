package com.shared.security.contracts.oauth

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pins the OIDC-registered snake_case field spellings + the ES256-only signing-alg list.
 * A rename of any wire field (e.g. `jwks_uri`) would break every relying party that reads
 * discovery; this test fails loudly if the @SerialName spellings drift.
 */
class OidcDiscoveryDocumentSerializationTest {
    private val json = Json { encodeDefaults = true }

    @Test
    fun `discovery document serializes with OIDC-registered field names`() {
        val doc =
            OidcDiscoveryDocument(
                issuer = "https://security-ops.example",
                authorizationEndpoint = "https://security-ops.example/authorize",
                tokenEndpoint = "https://security-ops.example/token",
                userinfoEndpoint = "https://security-ops.example/userinfo",
                jwksUri = "https://security-ops.example/v1/jwks",
                scopesSupported = listOf("openid"),
                responseTypesSupported = listOf("code"),
                grantTypesSupported = listOf("client_credentials"),
                tokenEndpointAuthMethodsSupported = listOf("tls_client_auth"),
                claimsSupported = listOf("sub"),
            )

        val text = json.encodeToString(OidcDiscoveryDocument.serializer(), doc)

        assertTrue(text.contains("\"jwks_uri\":\"https://security-ops.example/v1/jwks\""), text)
        assertTrue(text.contains("\"token_endpoint\""), text)
        assertTrue(text.contains("\"id_token_signing_alg_values_supported\":[\"ES256\"]"), text)
        assertTrue(text.contains("\"code_challenge_methods_supported\":[\"S256\"]"), text)
    }

    @Test
    fun `error response uses RFC 6749 snake_case error_description`() {
        val text =
            json.encodeToString(
                OAuthErrorResponse.serializer(),
                OAuthErrorResponse(error = OAuthErrorCode.INVALID_CLIENT.wireValue, errorDescription = "nope"),
            )
        assertTrue(text.contains("\"error\":\"invalid_client\""), text)
        assertTrue(text.contains("\"error_description\":\"nope\""), text)
    }

    @Test
    fun `error code wire round-trips`() {
        assertEquals(
            OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
            OAuthErrorCode.fromWireValue("unsupported_grant_type"),
        )
    }
}
