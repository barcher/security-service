package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.KekLifecycleStatus
import com.shared.security.application.ports.KekRecord
import com.shared.security.application.ports.KekRepository
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ListKeksObservationUseCaseTest {
    @Test
    fun `empty repository returns empty list and writes one DASHBOARD_OBSERVED row`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase = ListKeksObservationUseCase(StubKekRepo(emptyList()), audit)

            val result = useCase.execute(actorSubject = "CN=observer")

            assertTrue(result.isEmpty())
            assertEquals(1, audit.events.size)
            val event = audit.events.single()
            assertEquals(AuditEventType.DASHBOARD_OBSERVED, event.eventType)
            assertEquals("CN=observer", event.actorSubject)
            assertTrue(event.success)
        }

    @Test
    fun `populated repository maps each record to a KekObservation`() =
        runTest {
            val now = Clock.System.now()
            val records =
                listOf(
                    kek("kek-1", KekLifecycleStatus.ACTIVE, now),
                    kek("kek-2", KekLifecycleStatus.PRIOR, now),
                )
            val audit = RecordingAuditLog()
            val useCase = ListKeksObservationUseCase(StubKekRepo(records), audit)

            val result = useCase.execute(actorSubject = null)

            assertEquals(2, result.size)
            assertEquals("kek-1", result[0].id)
            assertEquals("ACTIVE", result[0].status)
            assertEquals("kek-2", result[1].id)
            assertEquals("PRIOR", result[1].status)
        }

    @Test
    fun `exactly one DASHBOARD_OBSERVED is written regardless of row count`() =
        runTest {
            val now = Clock.System.now()
            val records = (1..50).map { kek("kek-$it", KekLifecycleStatus.RETIRED, now) }
            val audit = RecordingAuditLog()
            val useCase = ListKeksObservationUseCase(StubKekRepo(records), audit)

            useCase.execute(actorSubject = "CN=observer")

            assertEquals(1, audit.events.size, "Exactly one audit row regardless of result-set size")
        }

    @Test
    fun `null actorSubject is preserved on the audit row`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase = ListKeksObservationUseCase(StubKekRepo(emptyList()), audit)

            useCase.execute(actorSubject = null)

            assertNull(audit.events.single().actorSubject)
        }

    private fun kek(
        id: String,
        status: KekLifecycleStatus,
        createdAt: Instant,
    ): KekRecord =
        KekRecord(
            id = id,
            fingerprint = "fp:$id",
            status = status,
            createdAt = createdAt,
            activatedAt = if (status != KekLifecycleStatus.STAGED) createdAt else null,
            quiescedAt = null,
            retiredAt = if (status == KekLifecycleStatus.RETIRED) createdAt else null,
        )

    private class StubKekRepo(private val all: List<KekRecord>) : KekRepository {
        override suspend fun findActive(): KekRecord? = all.firstOrNull { it.status == KekLifecycleStatus.ACTIVE }

        override suspend fun findAllPrior(): List<KekRecord> = all.filter { it.status == KekLifecycleStatus.PRIOR }

        override suspend fun findById(id: String): KekRecord? = all.firstOrNull { it.id == id }

        override suspend fun retirePrior(id: String): Boolean = error("not used")

        override suspend fun findAll(): List<KekRecord> = all
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }
}
