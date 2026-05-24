package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

class ListJwtSigningKeysObservationUseCaseTest {
    @Test
    fun `empty repository returns empty list and writes one DASHBOARD_OBSERVED`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase = ListJwtSigningKeysObservationUseCase(StubRepo(emptyList()), audit)

            val result = useCase.execute(actorSubject = "CN=observer")

            assertTrue(result.isEmpty())
            assertEquals(AuditEventType.DASHBOARD_OBSERVED, audit.events.single().eventType)
        }

    @Test
    fun `kid is hex-encoded and lifecycle fields are mapped through`() =
        runTest {
            val now = Clock.System.now()
            val kid = byteArrayOf(0x9d.toByte(), 0x3e, 0x8a.toByte(), 0xff.toByte())
            val rec =
                JwtSigningKeyRecord(
                    kid = kid,
                    status = JwtSigningKeyStatus.ACTIVE,
                    algorithm = "ES256",
                    curve = "P-256",
                    wrappedPrivateKeyBytes = byteArrayOf(0xDE.toByte(), 0xAD.toByte()),
                    publicKeySpki = byteArrayOf(0xBE.toByte(), 0xEF.toByte()),
                    wrappedUnderKekId = UUID.randomUUID().toString(),
                    createdAt = now,
                    activatedAt = now,
                    quiescedAt = null,
                    retiredAt = null,
                    retainUntil = null,
                )
            val useCase = ListJwtSigningKeysObservationUseCase(StubRepo(listOf(rec)), RecordingAuditLog())

            val result = useCase.execute(actorSubject = null).single()

            assertEquals("9d3e8aff", result.kidHex)
            assertEquals("ACTIVE", result.status)
            assertEquals("ES256", result.algorithm)
            assertEquals("P-256", result.curve)
            assertEquals(rec.wrappedUnderKekId, result.wrappedUnderKekId)
        }

    @Test
    fun `wrappedPrivateKeyBytes and publicKeySpki are NEVER surfaced on the DTO`() =
        runTest {
            val now = Clock.System.now()
            val rec =
                JwtSigningKeyRecord(
                    kid = ByteArray(16),
                    status = JwtSigningKeyStatus.ACTIVE,
                    algorithm = "ES256",
                    curve = "P-256",
                    wrappedPrivateKeyBytes = ByteArray(96) { 0x42.toByte() },
                    publicKeySpki = ByteArray(91) { 0x91.toByte() },
                    wrappedUnderKekId = "kek-1",
                    createdAt = now,
                    activatedAt = now,
                    quiescedAt = null,
                    retiredAt = null,
                    retainUntil = null,
                )
            val useCase = ListJwtSigningKeysObservationUseCase(StubRepo(listOf(rec)), RecordingAuditLog())

            val dto = useCase.execute(actorSubject = null).single()
            val dtoFields = dto.javaClass.declaredFields.map { it.name }

            assertTrue(
                "wrappedPrivateKeyBytes" !in dtoFields,
                "JwtSigningKeyObservation must not expose wrappedPrivateKeyBytes; got $dtoFields",
            )
            assertTrue(
                "publicKeySpki" !in dtoFields,
                "JwtSigningKeyObservation must not expose publicKeySpki; got $dtoFields",
            )
        }

    @Test
    fun `every lifecycle state is preserved in the DTO`() =
        runTest {
            val now = Clock.System.now()
            val records =
                JwtSigningKeyStatus.values().map { status ->
                    JwtSigningKeyRecord(
                        kid = ByteArray(16) { status.ordinal.toByte() },
                        status = status,
                        algorithm = "ES256",
                        curve = "P-256",
                        wrappedPrivateKeyBytes = ByteArray(0),
                        publicKeySpki = ByteArray(0),
                        wrappedUnderKekId = "kek-1",
                        createdAt = now,
                        activatedAt = if (status != JwtSigningKeyStatus.STAGED) now else null,
                        quiescedAt = null,
                        retiredAt = null,
                        retainUntil = null,
                    )
                }
            val useCase = ListJwtSigningKeysObservationUseCase(StubRepo(records), RecordingAuditLog())

            val statuses = useCase.execute(actorSubject = null).map { it.status }

            assertEquals(JwtSigningKeyStatus.values().map { it.name }, statuses)
        }

    private class StubRepo(private val all: List<JwtSigningKeyRecord>) : JwtSigningKeyRepository {
        override suspend fun findActive(): JwtSigningKeyRecord? {
            return all.firstOrNull { it.status == JwtSigningKeyStatus.ACTIVE }
        }

        override suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord> {
            return all.filter {
                it.status == JwtSigningKeyStatus.PRIOR || it.status == JwtSigningKeyStatus.QUIESCED
            }
        }

        override suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord? {
            return all.firstOrNull { it.kid.contentEquals(kid) }
        }

        override suspend fun findAllPublishable(): List<JwtSigningKeyRecord> = all

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

        override suspend fun findAll(): List<JwtSigningKeyRecord> = all
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }
}
