package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ListRecentRotationsObservationUseCaseTest {
    @Test
    fun `default N is 20 — request without n passes 20 to query port`() =
        runTest {
            val spy = SpyingQuery()
            val useCase = ListRecentRotationsObservationUseCase(spy, RecordingAuditLog())

            useCase.execute(actorSubject = "CN=observer")

            assertEquals(20, spy.lastSize)
        }

    @Test
    fun `n above MAX_N is clamped`() =
        runTest {
            val spy = SpyingQuery()
            val useCase = ListRecentRotationsObservationUseCase(spy, RecordingAuditLog())

            useCase.execute(actorSubject = null, n = 10_000)

            assertEquals(ListRecentRotationsObservationUseCase.MAX_N, spy.lastSize)
        }

    @Test
    fun `rotation filter is the locked five-event set`() =
        runTest {
            val spy = SpyingQuery()
            val useCase = ListRecentRotationsObservationUseCase(spy, RecordingAuditLog())

            useCase.execute(actorSubject = null)

            assertEquals(ListRecentRotationsObservationUseCase.ROTATION_EVENT_TYPES, spy.lastEventTypeIn)
            assertEquals(
                setOf(
                    "KEK_ACTIVATED",
                    "KEK_RETIRED",
                    "DEK_ROTATION_BATCH_OK",
                    "JWKS_KEY_ACTIVATED",
                    "JWKS_KEY_RETIRED",
                ),
                spy.lastEventTypeIn,
            )
        }

    @Test
    fun `n=0 raises IllegalArgumentException`() =
        runTest {
            val useCase = ListRecentRotationsObservationUseCase(SpyingQuery(), RecordingAuditLog())
            val thrown = runCatching { useCase.execute(actorSubject = null, n = 0) }.exceptionOrNull()
            assertTrue(thrown is IllegalArgumentException)
        }

    @Test
    fun `result rows are mapped to RotationObservation DTOs`() =
        runTest {
            val now = Clock.System.now()
            val rows =
                listOf(
                    AuditLogQueryPort.Row(
                        id = 1L,
                        occurredAt = now,
                        eventType = "KEK_ACTIVATED",
                        actorSubject = "CN=admin",
                        kekId = "kek-2",
                        dekHandle = null,
                        success = true,
                        detailJson = """{"fingerprint":"fp:abc"}""",
                    ),
                )
            val spy = SpyingQuery(result = AuditLogQueryPort.SearchResult(rows, 1))
            val useCase = ListRecentRotationsObservationUseCase(spy, RecordingAuditLog())

            val result = useCase.execute(actorSubject = null).single()

            assertEquals(1L, result.id)
            assertEquals("KEK_ACTIVATED", result.eventType)
            assertEquals("kek-2", result.kekId)
            assertEquals("""{"fingerprint":"fp:abc"}""", result.detailJson)
            assertEquals(AuditEventType.KEK_ACTIVATED, result.eventType)
        }

    private class SpyingQuery(
        private val result: AuditLogQueryPort.SearchResult = AuditLogQueryPort.SearchResult(emptyList(), 0),
    ) : AuditLogQueryPort {
        var lastEventTypeIn: Set<String>? = null
        var lastSize: Int = -1

        override suspend fun search(
            freeText: String?,
            eventTypeIn: Set<String>?,
            fromTime: Instant?,
            toTime: Instant?,
            page: Int,
            size: Int,
        ): AuditLogQueryPort.SearchResult {
            lastEventTypeIn = eventTypeIn
            lastSize = size
            return result
        }

        override suspend fun findById(id: Long): AuditLogQueryPort.Row? = null
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }
}
