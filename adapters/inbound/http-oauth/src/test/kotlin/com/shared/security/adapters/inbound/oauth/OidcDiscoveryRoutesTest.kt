package com.shared.security.adapters.inbound.oauth

import com.shared.security.application.usecases.oauth.BuildOidcDiscoveryUseCase
import com.shared.security.application.usecases.oauth.OidcProviderConfig
import com.shared.security.contracts.oauth.OidcDiscoveryDocument
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation

class OidcDiscoveryRoutesTest {
    @Test
    fun `discovery endpoint serves metadata with jwks_uri pointing at v1 jwks`() =
        testApplication {
            application {
                install(ServerContentNegotiation) { json(Json { encodeDefaults = true }) }
                val useCase = BuildOidcDiscoveryUseCase(OidcProviderConfig("https://security-ops.example"))
                routing { installOidcDiscoveryRoutes(useCase) }
            }
            val client =
                createClient {
                    install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
                }

            val response = client.get("/.well-known/openid-configuration")
            assertEquals(HttpStatusCode.OK, response.status)
            assertTrue(
                response.headers["Cache-Control"]?.contains("max-age") == true,
                "discovery should set a Cache-Control max-age",
            )

            val doc: OidcDiscoveryDocument = response.body()
            assertEquals("https://security-ops.example", doc.issuer)
            assertEquals("https://security-ops.example/v1/jwks", doc.jwksUri)
            assertEquals(listOf("ES256"), doc.idTokenSigningAlgValuesSupported)
            assertTrue(doc.grantTypesSupported.contains("client_credentials"))
            assertTrue(doc.tokenEndpointAuthMethodsSupported.contains("tls_client_auth"))
        }
}
