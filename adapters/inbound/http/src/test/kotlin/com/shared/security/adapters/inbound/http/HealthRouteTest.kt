package com.shared.security.adapters.inbound.http

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HealthRouteTest {
    @Test
    fun `health endpoint returns 200 with service identifier`() =
        testApplication {
            application {
                install(ContentNegotiation) { json() }
                routing { installHealthRoute() }
            }
            val response = client.get("/v1/health")
            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.bodyAsText()
            assertTrue(body.contains("\"status\":\"ok\""), "body was: $body")
            assertTrue(body.contains("\"service\":\"security-service\""), "body was: $body")
        }
}
