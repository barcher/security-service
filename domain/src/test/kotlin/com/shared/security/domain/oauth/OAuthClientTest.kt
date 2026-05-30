package com.shared.security.domain.oauth

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OAuthClientTest {
    private fun confidentialClient(
        enabled: Boolean = true,
        grants: Set<OAuthGrantType> = setOf(OAuthGrantType.CLIENT_CREDENTIALS),
    ) = OAuthClient(
        clientId = "workautomations-financial",
        authMethod = OAuthClientAuthMethod.TLS_CLIENT_AUTH,
        subjectDn = "CN=workautomations-financial-monolith,O=WorkAutomations",
        allowedGrantTypes = grants,
        allowedScopes = setOf(OAuthScope.of("crypto.dek")),
        allowedAudiences = setOf("workautomations-api"),
        enabled = enabled,
    )

    @Test
    fun `tls_client_auth client requires a subject DN`() {
        assertThrows(IllegalArgumentException::class.java) {
            OAuthClient(
                clientId = "x",
                authMethod = OAuthClientAuthMethod.TLS_CLIENT_AUTH,
                subjectDn = null,
                allowedGrantTypes = setOf(OAuthGrantType.CLIENT_CREDENTIALS),
                allowedScopes = emptySet(),
                allowedAudiences = emptySet(),
                enabled = true,
            )
        }
    }

    @Test
    fun `public client must not carry a subject DN`() {
        assertThrows(IllegalArgumentException::class.java) {
            OAuthClient(
                clientId = "workautomations-frontend",
                authMethod = OAuthClientAuthMethod.NONE,
                subjectDn = "CN=should-not-be-here",
                allowedGrantTypes = setOf(OAuthGrantType.AUTHORIZATION_CODE),
                allowedScopes = setOf(OAuthScope.OPENID),
                allowedAudiences = setOf("workautomations-api"),
                enabled = true,
            )
        }
    }

    @Test
    fun `allows is false for a disabled client`() {
        assertFalse(confidentialClient(enabled = false).allows(OAuthGrantType.CLIENT_CREDENTIALS))
    }

    @Test
    fun `allows is false for a grant the client is not provisioned for`() {
        assertFalse(confidentialClient().allows(OAuthGrantType.AUTHORIZATION_CODE))
        assertTrue(confidentialClient().allows(OAuthGrantType.CLIENT_CREDENTIALS))
    }

    @Test
    fun `scope rejects whitespace and blanks`() {
        assertThrows(IllegalArgumentException::class.java) { OAuthScope.of("a b") }
        assertThrows(IllegalArgumentException::class.java) { OAuthScope.of("  ") }
        assertEquals(listOf(OAuthScope.OPENID, OAuthScope.of("crypto.dek")), OAuthScope.parseList("openid crypto.dek"))
    }

    @Test
    fun `grant type wire round-trips`() {
        assertEquals(OAuthGrantType.CLIENT_CREDENTIALS, OAuthGrantType.fromWireValue("client_credentials"))
    }
}
