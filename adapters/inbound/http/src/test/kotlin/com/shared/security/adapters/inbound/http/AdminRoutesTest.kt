package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.auth.TestCertificateFactory
import com.shared.security.adapters.inbound.http.auth.TestPeerCertChainAttributeKey
import com.shared.security.adapters.inbound.http.auth.TestPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.installMtlsAuth
import com.shared.security.adapters.inbound.http.dto.KeyStatusResponse
import com.shared.security.adapters.inbound.http.dto.RotateKekResponse
import com.shared.security.application.ports.AdminAllowList
import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.KekPair
import com.shared.security.application.ports.WrappedDek
import com.shared.security.application.usecases.GenerateNewKekPairUseCase
import com.shared.security.application.usecases.GetKeyStatusUseCase
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation

class AdminRoutesTest {
    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events += event
        }
    }

    private class StubCryptoKeyService : CryptoKeyServicePort {
        override val isAvailable: Boolean = true

        override suspend fun generateDek() = error("not used")

        override suspend fun wrapDek(dekBytes: ByteArray) = error("not used")

        override suspend fun unwrapDek(wrapped: WrappedDek) = error("not used")

        override suspend fun rewrapDekForNewKek(
            existingWrapped: WrappedDek,
            newPublicKeyBytes: ByteArray,
        ) = error("not used")

        override fun generateNewKekPair() = KekPair(publicKeyB64 = "PUB-NEW", privateKeyB64 = "PRIV-NEW")

        override fun getPublicKeyFingerprint(): String = "fp:ab:cd"
    }

    private fun io.ktor.server.testing.ApplicationTestBuilder.installWiring(
        audit: AuditLogPort,
        adminSubjects: Set<String>,
        cert: X509Certificate,
    ) {
        val crypto = StubCryptoKeyService()
        application {
            install(ContentNegotiation) { json() }
            intercept(ApplicationCallPipeline.Setup) {
                context.attributes.put(TestPeerCertChainAttributeKey, arrayOf(cert))
            }
            installMtlsAuth(extractor = TestPeerCertChainExtractor(), auditLog = audit)
            routing {
                installAdminRoutes(
                    adminAllowList = AdminAllowList { it in adminSubjects },
                    auditLog = audit,
                    generateNewKekPair = GenerateNewKekPairUseCase(crypto, audit),
                    getKeyStatus = GetKeyStatusUseCase(crypto, audit),
                )
            }
        }
    }

    private fun jsonClient(builder: io.ktor.server.testing.ApplicationTestBuilder) =
        builder.createClient { install(ClientContentNegotiation) { json() } }

    @Test
    fun `POST v1 admin rotate-kek with admin subject returns new key material`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = "CN=admin,O=WorkAutomations")
            val adminDn = cert.subjectX500Principal.name
            installWiring(audit, adminSubjects = setOf(adminDn), cert = cert)
            val client = jsonClient(this)

            val response = client.post("/v1/admin/rotate-kek")

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<RotateKekResponse>()
            assertEquals("PUB-NEW", body.newPublicKeyB64)
            assertEquals("PRIV-NEW", body.newPrivateKeyB64)
            assertTrue(audit.events.any { it.eventType == AuditEventType.KEK_ROTATION_REQUESTED && it.success })
            assertEquals(0, audit.events.count { it.eventType == AuditEventType.ADMIN_FORBIDDEN })
        }

    @Test
    fun `POST v1 admin rotate-kek with non-admin subject returns 403 and writes ADMIN_FORBIDDEN audit`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = "CN=monolith,O=WorkAutomations")
            installWiring(audit, adminSubjects = emptySet(), cert = cert)
            val client = jsonClient(this)

            val response = client.post("/v1/admin/rotate-kek")

            assertEquals(HttpStatusCode.Forbidden, response.status)
            val forbidden = audit.events.firstOrNull { it.eventType == AuditEventType.ADMIN_FORBIDDEN }
            assertNotNull(forbidden)
            assertTrue(forbidden!!.detailJson!!.contains("rotate-kek"))
            assertEquals(0, audit.events.count { it.eventType == AuditEventType.KEK_ROTATION_REQUESTED })
        }

    @Test
    fun `GET v1 admin key-status with admin subject returns active KEK fingerprint`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = "CN=admin,O=WorkAutomations")
            installWiring(audit, adminSubjects = setOf(cert.subjectX500Principal.name), cert = cert)
            val client = jsonClient(this)

            val response = client.get("/v1/admin/key-status")

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<KeyStatusResponse>()
            assertEquals(true, body.isAvailable)
            assertEquals("fp:ab:cd", body.activeKekFingerprint)
            assertTrue(audit.events.any { it.eventType == AuditEventType.KEY_STATUS_VIEWED && it.success })
        }

    @Test
    fun `GET v1 admin key-status with non-admin subject returns 403`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = "CN=monolith,O=WorkAutomations")
            installWiring(audit, adminSubjects = emptySet(), cert = cert)
            val client = jsonClient(this)

            val response = client.get("/v1/admin/key-status")

            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertEquals(0, audit.events.count { it.eventType == AuditEventType.KEY_STATUS_VIEWED })
            assertTrue(audit.events.any { it.eventType == AuditEventType.ADMIN_FORBIDDEN })
        }
}
