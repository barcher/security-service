package com.shared.security.adapters.inbound.http.auth

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MtlsAuthPluginTest {
    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events += event
        }
    }

    @Test
    fun `call without a client certificate is rejected with HTTP 401`() =
        testApplication {
            val audit = RecordingAuditLog()
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(extractor = DenyAllPeerCertChainExtractor(), auditLog = audit)
                routing {
                    get("/v1/protected") { call.respond(HttpStatusCode.OK, mapOf("ok" to true)) }
                }
            }

            val response = client.get("/v1/protected")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertTrue(response.bodyAsText().contains("mtls_required"))
        }

    @Test
    fun `MTLS_REJECTED audit event is written on rejection`() =
        testApplication {
            val audit = RecordingAuditLog()
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(extractor = DenyAllPeerCertChainExtractor(), auditLog = audit)
                routing {
                    get("/v1/protected") { call.respond(HttpStatusCode.OK, mapOf("ok" to true)) }
                }
            }

            client.get("/v1/protected")

            assertEquals(1, audit.events.size)
            val event = audit.events.first()
            assertEquals(AuditEventType.MTLS_REJECTED, event.eventType)
            assertNull(event.actorSubject)
            assertEquals(false, event.success)
            assertTrue(event.detailJson?.contains("/v1/protected") == true)
        }

    @Test
    fun `rejected call short-circuits before route handler runs`() =
        testApplication {
            val audit = RecordingAuditLog()
            var routeRan = false
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(extractor = DenyAllPeerCertChainExtractor(), auditLog = audit)
                routing {
                    get("/v1/protected") {
                        routeRan = true
                        call.respond(HttpStatusCode.OK, mapOf("ok" to true))
                    }
                }
            }

            client.get("/v1/protected")

            assertEquals(false, routeRan)
        }

    @Test
    fun `call with a valid client certificate passes and exposes ClientPrincipal`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = "CN=monolith,O=WorkAutomations")
            val extractor = TestPeerCertChainExtractor()
            var seenPrincipalSubject: String? = null
            var seenFingerprintLength = -1

            application {
                install(ContentNegotiation) { json() }
                intercept(io.ktor.server.application.ApplicationCallPipeline.Setup) {
                    context.attributes.put(TestPeerCertChainAttributeKey, arrayOf(cert))
                }
                installMtlsAuth(extractor = extractor, auditLog = audit)
                routing {
                    get("/v1/protected") {
                        val p = call.clientPrincipal()
                        seenPrincipalSubject = p?.subjectDn
                        seenFingerprintLength = p?.certFingerprint?.length ?: -1
                        call.respond(HttpStatusCode.OK, mapOf("ok" to true))
                    }
                }
            }

            val response = client.get("/v1/protected")

            assertEquals(HttpStatusCode.OK, response.status)
            assertNotNull(seenPrincipalSubject)
            // X500 RFC2253 form orders attributes from most-specific to least-specific (right-to-left
            // relative to the cert encoding), so the leaf CN appears last, not first.
            assertTrue(
                seenPrincipalSubject!!.contains("CN=monolith"),
                "expected subject to contain CN=monolith, got: $seenPrincipalSubject",
            )
            assertTrue(
                seenPrincipalSubject!!.contains("O=WorkAutomations"),
                "expected subject to contain O=WorkAutomations, got: $seenPrincipalSubject",
            )
            // 32 bytes × 2 hex chars + 31 colons = 95 characters
            assertEquals(95, seenFingerprintLength)
            assertEquals(0, audit.events.size)
        }

    @Test
    fun `empty chain is treated identically to a missing chain`() =
        testApplication {
            val audit = RecordingAuditLog()
            val extractor =
                PeerCertChainExtractor { _ -> emptyArray() }
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(extractor = extractor, auditLog = audit)
                routing {
                    get("/v1/protected") { call.respond(HttpStatusCode.OK, mapOf("ok" to true)) }
                }
            }

            val response = client.get("/v1/protected")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals(1, audit.events.size)
            assertEquals(AuditEventType.MTLS_REJECTED, audit.events.first().eventType)
        }

    @Test
    fun `health endpoint without auth 401s when not on public allow-list (default behavior)`() =
        testApplication {
            val audit = RecordingAuditLog()
            application {
                install(ContentNegotiation) { json() }
                // Default install — empty publicPathPrefixes — every route is gated.
                installMtlsAuth(extractor = DenyAllPeerCertChainExtractor(), auditLog = audit)
                routing {
                    get("/v1/health") { call.respond(HttpStatusCode.OK, mapOf("status" to "ok")) }
                }
            }

            val response = client.get("/v1/health")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
        }

    @Test
    fun `public allow-listed path is reachable without any client cert`() =
        testApplication {
            val audit = RecordingAuditLog()
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(
                    extractor = DenyAllPeerCertChainExtractor(),
                    auditLog = audit,
                    publicPathPrefixes = setOf("/v1/jwks", "/v1/health"),
                )
                routing {
                    get("/v1/jwks") { call.respond(HttpStatusCode.OK, mapOf("keys" to emptyList<String>())) }
                    get("/v1/health") { call.respond(HttpStatusCode.OK, mapOf("status" to "ok")) }
                }
            }

            val jwks = client.get("/v1/jwks")
            val health = client.get("/v1/health")

            assertEquals(HttpStatusCode.OK, jwks.status)
            assertEquals(HttpStatusCode.OK, health.status)
            // Allow-list bypass MUST NOT write an MTLS_REJECTED audit event.
            assertEquals(0, audit.events.size)
        }

    @Test
    fun `non-allow-listed path is still 401 even when allow-list is configured`() =
        testApplication {
            val audit = RecordingAuditLog()
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(
                    extractor = DenyAllPeerCertChainExtractor(),
                    auditLog = audit,
                    publicPathPrefixes = setOf("/v1/jwks", "/v1/health"),
                )
                routing {
                    get("/v1/dek/unwrap") { call.respond(HttpStatusCode.OK, mapOf("ok" to true)) }
                }
            }

            val response = client.get("/v1/dek/unwrap")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertTrue(response.bodyAsText().contains("mtls_required"))
            assertEquals(1, audit.events.size)
            assertEquals(AuditEventType.MTLS_REJECTED, audit.events.first().eventType)
        }

    @Test
    fun `allow-list matches prefix exactly, not as substring`() =
        testApplication {
            // `/v1/jwks-other` must NOT match the `/v1/jwks` allow-list entry — startsWith on a
            // bare prefix would mis-match; the implementation requires either exact equality
            // or a `/` or `?` boundary after the prefix.
            val audit = RecordingAuditLog()
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(
                    extractor = DenyAllPeerCertChainExtractor(),
                    auditLog = audit,
                    publicPathPrefixes = setOf("/v1/jwks"),
                )
                routing {
                    get("/v1/jwks-other") { call.respond(HttpStatusCode.OK, mapOf("ok" to true)) }
                }
            }

            val response = client.get("/v1/jwks-other")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
        }
}
