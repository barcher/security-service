package com.shared.security.application.usecases.oauth

import com.shared.security.application.ports.OAuthClientStore
import com.shared.security.domain.oauth.OAuthClient
import com.shared.security.domain.oauth.OAuthClientAuthMethod
import com.shared.security.domain.oauth.OAuthGrantType
import com.shared.security.domain.oauth.OAuthScope
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BuildOidcDiscoveryUseCaseTest {
    @Test
    fun `discovery jwks_uri points at the existing v1 jwks route`() {
        val config = OidcProviderConfig(issuer = "https://security-ops.example")
        val metadata = BuildOidcDiscoveryUseCase(config).build()

        assertEquals("https://security-ops.example/v1/jwks", metadata.jwksUri)
        assertEquals("https://security-ops.example/token", metadata.tokenEndpoint)
        assertEquals("https://security-ops.example", metadata.issuer)
        assertTrue(metadata.grantTypesSupported.contains("client_credentials"))
        assertTrue(metadata.responseTypesSupported == listOf("code"))
        assertTrue(metadata.tokenEndpointAuthMethodsSupported.contains("tls_client_auth"))
    }

    @Test
    fun `issuer with trailing slash is rejected`() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException::class.java) {
            OidcProviderConfig(issuer = "https://security-ops.example/")
        }
    }

    @Test
    fun `seed inserts only absent clients and is idempotent`() =
        runTest {
            val store = InMemoryClientStore()
            val clients =
                listOf(
                    client("workautomations-financial"),
                    client("workautomations-monolith"),
                )
            val useCase = SeedOAuthClientsUseCase(store, clients)

            assertEquals(2, useCase.seed())
            // Second run inserts nothing — idempotent boot-time seed.
            assertEquals(0, useCase.seed())
            assertEquals(2, store.inserted.size)
        }

    private fun client(id: String) =
        OAuthClient(
            clientId = id,
            authMethod = OAuthClientAuthMethod.TLS_CLIENT_AUTH,
            subjectDn = "CN=$id,O=WorkAutomations",
            allowedGrantTypes = setOf(OAuthGrantType.CLIENT_CREDENTIALS),
            allowedScopes = setOf(OAuthScope.of("crypto.dek")),
            allowedAudiences = setOf("workautomations-api"),
            enabled = true,
        )

    private class InMemoryClientStore : OAuthClientStore {
        val inserted = mutableMapOf<String, OAuthClient>()

        override suspend fun insertIfAbsent(client: OAuthClient): Boolean {
            if (inserted.containsKey(client.clientId)) return false
            inserted[client.clientId] = client
            return true
        }
    }
}
