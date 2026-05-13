package com.workautomations.security.adapters.inbound.http

import com.workautomations.security.adapters.inbound.http.auth.TestCertificateFactory
import com.workautomations.security.adapters.inbound.http.auth.TestPeerCertChainAttributeKey
import com.workautomations.security.adapters.inbound.http.auth.TestPeerCertChainExtractor
import com.workautomations.security.adapters.inbound.http.auth.installMtlsAuth
import com.workautomations.security.adapters.inbound.http.dto.GenerateDekResponse
import com.workautomations.security.adapters.inbound.http.dto.RewrapDekRequest
import com.workautomations.security.adapters.inbound.http.dto.RewrapDekResponse
import com.workautomations.security.adapters.inbound.http.dto.UnwrapDekRequest
import com.workautomations.security.adapters.inbound.http.dto.UnwrapDekResponse
import com.workautomations.security.adapters.inbound.http.dto.WrapDekRequest
import com.workautomations.security.adapters.inbound.http.dto.WrapDekResponse
import com.workautomations.security.adapters.inbound.http.dto.WrappedDekDto
import com.workautomations.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditEventType
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.application.ports.CryptoKeyServicePort
import com.workautomations.security.application.ports.KekPair
import com.workautomations.security.application.ports.WrappedDek
import com.workautomations.security.application.usecases.GenerateDekUseCase
import com.workautomations.security.application.usecases.RewrapDekUseCase
import com.workautomations.security.application.usecases.UnwrapDekUseCase
import com.workautomations.security.application.usecases.WrapDekUseCase
import io.ktor.client.call.body
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
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
import java.util.Base64
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation

class CryptoRoutesTest {
    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events += event
        }
    }

    // A real ML-KEM-backed CryptoKeyServicePort isn't reachable from this module (it would
    // import the crypto adapter, which the http adapter must not depend on). We use a small
    // in-memory fake that round-trips through a constant-key XOR — enough to verify wire
    // behaviour without dragging in BouncyCastle/ML-KEM here.
    private class FakeCryptoKeyService : CryptoKeyServicePort {
        override val isAvailable: Boolean = true
        private val cell = ByteArray(32) { (it + 1).toByte() }

        override suspend fun generateDek() =
            CryptoKeyServicePort.GeneratedDek(
                wrapped = WrappedDek(kemCiphertextB64 = "KEM", encryptedDekB64 = encode(cell)),
                plaintextBytes = cell.copyOf(),
            )

        override suspend fun wrapDek(dekBytes: ByteArray): WrappedDek =
            WrappedDek(kemCiphertextB64 = "KEM", encryptedDekB64 = encode(dekBytes))

        override suspend fun unwrapDek(wrapped: WrappedDek): ByteArray = decode(wrapped.encryptedDekB64)

        override suspend fun rewrapDekForNewKek(
            existingWrapped: WrappedDek,
            newPublicKeyBytes: ByteArray,
        ): WrappedDek = WrappedDek(kemCiphertextB64 = "KEM-new", encryptedDekB64 = existingWrapped.encryptedDekB64)

        override fun generateNewKekPair(): KekPair = KekPair(publicKeyB64 = "PUB", privateKeyB64 = "PRIV")

        override fun getPublicKeyFingerprint(): String = "fp:test"

        private fun encode(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

        private fun decode(b64: String) = Base64.getDecoder().decode(b64)
    }

    private fun io.ktor.server.testing.ApplicationTestBuilder.installStandardWiring(
        audit: AuditLogPort,
        unwrapRateLimiter: PerSubjectRateLimiter? = null,
    ) {
        val crypto = FakeCryptoKeyService()
        val cert = TestCertificateFactory.generate(subjectDn = "CN=monolith,O=WorkAutomations")

        application {
            install(ContentNegotiation) { json() }
            intercept(ApplicationCallPipeline.Setup) {
                context.attributes.put(TestPeerCertChainAttributeKey, arrayOf(cert))
            }
            installMtlsAuth(extractor = TestPeerCertChainExtractor(), auditLog = audit)
            routing {
                installCryptoRoutes(
                    generateDek = GenerateDekUseCase(crypto, audit),
                    wrapDek = WrapDekUseCase(crypto, audit),
                    unwrapDek = UnwrapDekUseCase(crypto, audit),
                    rewrapDek = RewrapDekUseCase(crypto, audit),
                    unwrapRateLimiter = unwrapRateLimiter,
                    auditLog = audit,
                )
            }
        }
    }

    private fun jsonClient(builder: io.ktor.server.testing.ApplicationTestBuilder) =
        builder.createClient {
            install(ClientContentNegotiation) { json() }
        }

    @Test
    fun `POST v1 dek generate returns wrapped + plaintext DEK and writes DEK_GENERATED audit`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)

            val response = client.post("/v1/dek/generate")

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<GenerateDekResponse>()
            assertTrue(body.plaintextDekB64.isNotBlank())
            assertEquals("KEM", body.wrapped.kemCiphertextB64)
            assertTrue(audit.events.any { it.eventType == AuditEventType.DEK_GENERATED && it.success })
            val firstGen = audit.events.first { it.eventType == AuditEventType.DEK_GENERATED }
            assertTrue(firstGen.actorSubject!!.contains("CN=monolith"))
        }

    @Test
    fun `POST v1 dek wrap accepts a 32-byte plaintext and returns wrapped`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)
            val dek = ByteArray(32) { 7 }

            val response =
                client.post("/v1/dek/wrap") {
                    contentType(ContentType.Application.Json)
                    setBody(WrapDekRequest(dekBytesB64 = Base64.getEncoder().encodeToString(dek)))
                }

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<WrapDekResponse>()
            assertEquals("KEM", body.wrapped.kemCiphertextB64)
            assertTrue(audit.events.any { it.eventType == AuditEventType.DEK_WRAPPED && it.success })
        }

    @Test
    fun `POST v1 dek wrap rejects payload with wrong DEK size`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)
            val tooShort = ByteArray(16) { 1 }

            val response =
                client.post("/v1/dek/wrap") {
                    contentType(ContentType.Application.Json)
                    setBody(WrapDekRequest(dekBytesB64 = Base64.getEncoder().encodeToString(tooShort)))
                }

            assertEquals(HttpStatusCode.UnprocessableEntity, response.status)
            assertTrue(audit.events.none { it.eventType == AuditEventType.DEK_WRAPPED })
        }

    @Test
    fun `POST v1 dek wrap rejects payload with malformed base64`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)

            val response =
                client.post("/v1/dek/wrap") {
                    contentType(ContentType.Application.Json)
                    setBody(WrapDekRequest(dekBytesB64 = "not!!base64!!"))
                }

            assertEquals(HttpStatusCode.UnprocessableEntity, response.status)
        }

    @Test
    fun `POST v1 dek unwrap returns plaintext DEK and writes DEK_UNWRAPPED audit`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)
            val original = ByteArray(32) { 11 }
            val originalB64 = Base64.getEncoder().encodeToString(original)
            val wrapped = WrappedDekDto(kemCiphertextB64 = "KEM", encryptedDekB64 = originalB64)

            val response =
                client.post("/v1/dek/unwrap") {
                    contentType(ContentType.Application.Json)
                    setBody(UnwrapDekRequest(wrapped = wrapped))
                }

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<UnwrapDekResponse>()
            assertEquals(original.toList(), Base64.getDecoder().decode(body.plaintextDekB64).toList())
            assertTrue(audit.events.any { it.eventType == AuditEventType.DEK_UNWRAPPED && it.success })
        }

    @Test
    fun `POST v1 dek rewrap re-wraps and writes DEK_REWRAPPED audit`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)
            val existing = WrappedDekDto(kemCiphertextB64 = "KEM-old", encryptedDekB64 = "ZGVrLWJ5dGVz")
            val newPub = Base64.getEncoder().encodeToString(ByteArray(64) { 1 })

            val response =
                client.post("/v1/dek/rewrap") {
                    contentType(ContentType.Application.Json)
                    setBody(RewrapDekRequest(existing = existing, newPublicKeyB64 = newPub))
                }

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<RewrapDekResponse>()
            assertEquals("KEM-new", body.wrapped.kemCiphertextB64)
            assertNotNull(audit.events.firstOrNull { it.eventType == AuditEventType.DEK_REWRAPPED })
        }

    @Test
    fun `POST v1 dek unwrap returns 429 + RATE_LIMIT_EXCEEDED audit when over cap`() =
        testApplication {
            val audit = RecordingAuditLog()
            val testClock =
                object : kotlinx.datetime.Clock {
                    override fun now() = kotlinx.datetime.Instant.fromEpochMilliseconds(0)
                }
            val limiter =
                PerSubjectRateLimiter(capacity = 1.0, refillTokensPerSecond = 0.01, clock = testClock)
            installStandardWiring(audit, unwrapRateLimiter = limiter)
            val client = jsonClient(this)
            val emptyDekB64 = Base64.getEncoder().encodeToString(ByteArray(32))
            val wrapped = WrappedDekDto(kemCiphertextB64 = "KEM", encryptedDekB64 = emptyDekB64)
            val body = UnwrapDekRequest(wrapped = wrapped)

            // First call consumes the only token → 200.
            val ok =
                client.post("/v1/dek/unwrap") {
                    contentType(ContentType.Application.Json)
                    setBody(body)
                }
            assertEquals(HttpStatusCode.OK, ok.status)

            // Second call (clock still at 0, refill rate 0.01/s → 0 tokens regenerated) → 429.
            val limited =
                client.post("/v1/dek/unwrap") {
                    contentType(ContentType.Application.Json)
                    setBody(body)
                }
            assertEquals(HttpStatusCode.TooManyRequests, limited.status)
            assertTrue(audit.events.any { it.eventType == AuditEventType.RATE_LIMIT_EXCEEDED && it.success == false })
            // The /v1/dek/unwrap endpoint was the one rate-limited.
            assertTrue(
                audit.events.first { it.eventType == AuditEventType.RATE_LIMIT_EXCEEDED }
                    .detailJson!!
                    .contains("/v1/dek/unwrap"),
            )
        }

    @Test
    fun `POST v1 dek rewrap rejects malformed new public key base64`() =
        testApplication {
            val audit = RecordingAuditLog()
            installStandardWiring(audit)
            val client = jsonClient(this)

            val response =
                client.post("/v1/dek/rewrap") {
                    contentType(ContentType.Application.Json)
                    setBody(
                        RewrapDekRequest(
                            existing = WrappedDekDto(kemCiphertextB64 = "x", encryptedDekB64 = "y"),
                            newPublicKeyB64 = "!!bad!!",
                        ),
                    )
                }

            assertEquals(HttpStatusCode.UnprocessableEntity, response.status)
        }
}
