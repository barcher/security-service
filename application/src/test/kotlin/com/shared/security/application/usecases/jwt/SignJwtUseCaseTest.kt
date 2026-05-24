package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtAudienceAllowList
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import com.shared.security.application.ports.KekEnvelopePort
import com.shared.security.application.ports.WrappedBlob
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.random.Random

class SignJwtUseCaseTest {
    @Test
    fun `audience not allow-listed returns AudienceForbidden and emits audit`() =
        runTest {
            val audit = RecordingAuditLog()
            val sut =
                SignJwtUseCase(
                    repo = StubRepo(active = null),
                    kekEnvelope = NoopKekEnvelope,
                    signing = NoopSigning,
                    audienceAllowList = DenyAllAllowList,
                    auditLog = audit,
                )

            val result =
                sut.execute(
                    SignJwtUseCase.Request(
                        subjectDn = "CN=monolith",
                        subject = "user-1",
                        audience = "forbidden-aud",
                        issuer = "security-service",
                        expiresInSeconds = 60,
                    ),
                )

            assertEquals(SignJwtUseCase.Result.AudienceForbidden, result)
            assertEquals(1, audit.events.size)
            assertEquals(AuditEventType.JWT_AUDIENCE_FORBIDDEN, audit.events[0].eventType)
            assertEquals(false, audit.events[0].success)
        }

    @Test
    fun `no ACTIVE key returns NoActiveKey and emits audit`() =
        runTest {
            val audit = RecordingAuditLog()
            val sut =
                SignJwtUseCase(
                    repo = StubRepo(active = null),
                    kekEnvelope = NoopKekEnvelope,
                    signing = NoopSigning,
                    audienceAllowList = AllowAllAllowList,
                    auditLog = audit,
                )

            val result =
                sut.execute(
                    SignJwtUseCase.Request(
                        subjectDn = "CN=monolith",
                        subject = "user-1",
                        audience = "any-aud",
                        issuer = "security-service",
                        expiresInSeconds = 60,
                    ),
                )

            assertEquals(SignJwtUseCase.Result.NoActiveKey, result)
            assertEquals(AuditEventType.JWT_SIGN_FAILED, audit.events.single().eventType)
        }

    @Test
    fun `happy path emits JWT_SIGNED and returns three-segment token with kid header`() =
        runTest {
            val activeKey =
                JwtSigningKeyRecord(
                    kid = Random.nextBytes(16),
                    status = JwtSigningKeyStatus.ACTIVE,
                    algorithm = "ES256",
                    curve = "P-256",
                    wrappedPrivateKeyBytes =
                        WrappedBlobCodec.encode(
                            WrappedBlob(
                                kemCiphertextB64 = "kem",
                                encryptedBytesB64 = "enc",
                                algorithm = "ML-KEM-768/AES-256-GCM",
                                kekId = "kek-1",
                            ),
                        ),
                    publicKeySpki = Random.nextBytes(91),
                    wrappedUnderKekId = "kek-1",
                    createdAt = Clock.System.now(),
                    activatedAt = Clock.System.now(),
                    quiescedAt = null,
                    retiredAt = null,
                    retainUntil = null,
                )
            val audit = RecordingAuditLog()
            val signing = StubSigning(returnSignature = ByteArray(64) { 0xAB.toByte() })
            val sut =
                SignJwtUseCase(
                    repo = StubRepo(active = activeKey),
                    kekEnvelope = StubKekEnvelope(returnPlaintext = Random.nextBytes(48)),
                    signing = signing,
                    audienceAllowList = AllowAllAllowList,
                    auditLog = audit,
                )

            val result =
                sut.execute(
                    SignJwtUseCase.Request(
                        subjectDn = "CN=monolith",
                        subject = "user-42",
                        audience = "workautomations-api",
                        issuer = "security-service",
                        expiresInSeconds = 300,
                    ),
                )

            assertTrue(result is SignJwtUseCase.Result.Signed)
            val token = (result as SignJwtUseCase.Result.Signed).token
            val parts = token.split(".")
            assertEquals(3, parts.size, "JWS compact serialization is header.payload.signature")
            val header = String(Base64.getUrlDecoder().decode(parts[0]), Charsets.UTF_8)
            assertTrue(header.contains("\"alg\":\"ES256\""))
            assertTrue(header.contains("\"kid\":\"${activeKey.kid.toHex()}\""))
            val payload = String(Base64.getUrlDecoder().decode(parts[1]), Charsets.UTF_8)
            assertTrue(payload.contains("\"aud\":\"workautomations-api\""))
            assertTrue(payload.contains("\"sub\":\"user-42\""))
            assertEquals(AuditEventType.JWT_SIGNED, audit.events.single().eventType)
        }

    // --- stubs ---

    private class StubRepo(private val active: JwtSigningKeyRecord?) : JwtSigningKeyRepository {
        override suspend fun findActive(): JwtSigningKeyRecord? = active

        override suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord> = emptyList()

        override suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord? = null

        override suspend fun findAllPublishable(): List<JwtSigningKeyRecord> = listOfNotNull(active)

        override suspend fun insertStaged(record: JwtSigningKeyRecord) = error("not used")

        override suspend fun activate(
            kid: ByteArray,
            now: Instant,
        ): Boolean = error("not used")

        override suspend fun quiescePrior(
            kid: ByteArray,
            now: Instant,
        ): Boolean = error("not used")

        override suspend fun retireQuiesced(
            kid: ByteArray,
            now: Instant,
            retentionDays: Long,
        ): Boolean = error("not used")

        override suspend fun deleteRetired(kid: ByteArray): Boolean = error("not used")

        override suspend fun findRetiredEligibleForDelete(now: Instant): List<JwtSigningKeyRecord> = emptyList()

        override suspend fun findAll(): List<JwtSigningKeyRecord> = listOfNotNull(active)
    }

    private class StubKekEnvelope(private val returnPlaintext: ByteArray) : KekEnvelopePort {
        override suspend fun wrap(
            plaintext: ByteArray,
            aad: ByteArray,
        ): WrappedBlob = error("not used")

        override suspend fun unwrap(
            wrapped: WrappedBlob,
            aad: ByteArray,
        ): ByteArray = returnPlaintext.copyOf()
    }

    private object NoopKekEnvelope : KekEnvelopePort {
        override suspend fun wrap(
            plaintext: ByteArray,
            aad: ByteArray,
        ): WrappedBlob = error("not used")

        override suspend fun unwrap(
            wrapped: WrappedBlob,
            aad: ByteArray,
        ): ByteArray = error("not used")
    }

    private class StubSigning(private val returnSignature: ByteArray) : JwtSigningKeyPort {
        override fun generateKeyPair(): GeneratedKeyPair = error("not used")

        override fun sign(
            privateKeyPkcs8: ByteArray,
            payload: ByteArray,
        ): ByteArray = returnSignature

        override fun verify(
            publicKeySpki: ByteArray,
            payload: ByteArray,
            signature: ByteArray,
        ): Boolean = true

        override fun computeKid(publicKeySpki: ByteArray): ByteArray = ByteArray(16)

        override fun spkiToJwkXY(publicKeySpki: ByteArray): JwkCoords = JwkCoords("x", "y")
    }

    private object NoopSigning : JwtSigningKeyPort {
        override fun generateKeyPair(): GeneratedKeyPair = error("not used")

        override fun sign(
            privateKeyPkcs8: ByteArray,
            payload: ByteArray,
        ): ByteArray = error("not used")

        override fun verify(
            publicKeySpki: ByteArray,
            payload: ByteArray,
            signature: ByteArray,
        ): Boolean = error("not used")

        override fun computeKid(publicKeySpki: ByteArray): ByteArray = error("not used")

        override fun spkiToJwkXY(publicKeySpki: ByteArray): JwkCoords = error("not used")
    }

    private object AllowAllAllowList : JwtAudienceAllowList {
        override fun isAllowed(
            subjectDn: String,
            audience: String,
        ): Boolean = true
    }

    private object DenyAllAllowList : JwtAudienceAllowList {
        override fun isAllowed(
            subjectDn: String,
            audience: String,
        ): Boolean = false
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }
}
