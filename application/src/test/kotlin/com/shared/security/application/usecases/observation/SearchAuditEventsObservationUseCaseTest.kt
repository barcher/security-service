package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SearchAuditEventsObservationUseCaseTest {
    @Test
    fun `empty result returns empty page and writes one audit row`() =
        runTest {
            val audit = RecordingAuditLog()
            val empty = AuditLogQueryPort.SearchResult(emptyList(), 0)
            val useCase = SearchAuditEventsObservationUseCase(StubQuery(empty), audit)

            val page = useCase.execute(actorSubject = "CN=observer")

            assertTrue(page.items.isEmpty())
            assertEquals(0L, page.totalCount)
            assertEquals(1, audit.events.size)
        }

    @Test
    fun `default page size is 50 — request without size hits the default`() =
        runTest {
            val spy = SpyingQuery(AuditLogQueryPort.SearchResult(emptyList(), 0))
            val useCase = SearchAuditEventsObservationUseCase(spy, RecordingAuditLog())

            useCase.execute(actorSubject = null)

            assertEquals(50, spy.lastSize)
        }

    @Test
    fun `explicit size above cap is clamped to MAX_PAGE_SIZE`() =
        runTest {
            val spy = SpyingQuery(AuditLogQueryPort.SearchResult(emptyList(), 0))
            val useCase = SearchAuditEventsObservationUseCase(spy, RecordingAuditLog())

            useCase.execute(actorSubject = null, size = 10_000)

            assertEquals(SearchAuditEventsObservationUseCase.MAX_PAGE_SIZE, spy.lastSize)
        }

    @Test
    fun `filters are forwarded to the query port`() =
        runTest {
            val spy = SpyingQuery(AuditLogQueryPort.SearchResult(emptyList(), 0))
            val useCase = SearchAuditEventsObservationUseCase(spy, RecordingAuditLog())
            val from = Instant.parse("2026-05-01T00:00:00Z")
            val to = Instant.parse("2026-05-31T23:59:59Z")

            useCase.execute(
                actorSubject = "CN=observer",
                freeText = "needle",
                eventTypeIn = setOf("KEK_ACTIVATED"),
                fromTime = from,
                toTime = to,
                page = 2,
                size = 25,
            )

            assertEquals("needle", spy.lastFreeText)
            assertEquals(setOf("KEK_ACTIVATED"), spy.lastEventTypeIn)
            assertEquals(from, spy.lastFromTime)
            assertEquals(to, spy.lastToTime)
            assertEquals(2, spy.lastPage)
            assertEquals(25, spy.lastSize)
        }

    @Test
    fun `dekHandle is hex-encoded in the observation DTO`() =
        runTest {
            val now = Clock.System.now()
            val row =
                AuditLogQueryPort.Row(
                    id = 1L,
                    occurredAt = now,
                    eventType = "DEK_UNWRAPPED",
                    actorSubject = "CN=svc",
                    kekId = "kek-1",
                    dekHandle = byteArrayOf(0x01, 0xff.toByte()),
                    success = true,
                    detailJson = null,
                )
            val result = AuditLogQueryPort.SearchResult(listOf(row), 1)
            val useCase = SearchAuditEventsObservationUseCase(StubQuery(result), RecordingAuditLog())

            val page = useCase.execute(actorSubject = null)

            assertEquals("01ff", page.items.single().dekHandleHex)
        }

    @Test
    fun `null dekHandle produces null hex`() =
        runTest {
            val now = Clock.System.now()
            val row =
                AuditLogQueryPort.Row(
                    id = 1L,
                    occurredAt = now,
                    eventType = "KEK_ACTIVATED",
                    actorSubject = null,
                    kekId = null,
                    dekHandle = null,
                    success = true,
                    detailJson = null,
                )
            val result = AuditLogQueryPort.SearchResult(listOf(row), 1)
            val useCase = SearchAuditEventsObservationUseCase(StubQuery(result), RecordingAuditLog())

            val page = useCase.execute(actorSubject = null)

            assertNull(page.items.single().dekHandleHex)
        }

    @Test
    fun `page and pageSize are reflected on the response`() =
        runTest {
            val result = AuditLogQueryPort.SearchResult(emptyList(), 0)
            val useCase = SearchAuditEventsObservationUseCase(StubQuery(result), RecordingAuditLog())

            val page = useCase.execute(actorSubject = null, page = 3, size = 17)

            assertEquals(3, page.page)
            assertEquals(17, page.pageSize)
        }

    @Test
    fun `audit detailJson includes page metadata`() =
        runTest {
            val audit = RecordingAuditLog()
            val result = AuditLogQueryPort.SearchResult(emptyList(), 999)
            val useCase = SearchAuditEventsObservationUseCase(StubQuery(result), audit)

            useCase.execute(actorSubject = null, page = 7, size = 33)

            val event = audit.events.single()
            assertTrue(event.detailJson!!.contains("\"page\":7"))
            assertTrue(event.detailJson.contains("\"size\":33"))
            assertTrue(event.detailJson.contains("\"totalCount\":999"))
            assertTrue(event.detailJson.contains("\"resource\":\"audit-events\""))
        }

    private open class StubQuery(private val result: AuditLogQueryPort.SearchResult) : AuditLogQueryPort {
        override suspend fun search(
            freeText: String?,
            eventTypeIn: Set<String>?,
            fromTime: Instant?,
            toTime: Instant?,
            page: Int,
            size: Int,
        ): AuditLogQueryPort.SearchResult = result

        override suspend fun findById(id: Long): AuditLogQueryPort.Row? = null
    }

    private class SpyingQuery(result: AuditLogQueryPort.SearchResult) : StubQuery(result) {
        var lastFreeText: String? = null
        var lastEventTypeIn: Set<String>? = null
        var lastFromTime: Instant? = null
        var lastToTime: Instant? = null
        var lastPage: Int = -1
        var lastSize: Int = -1

        override suspend fun search(
            freeText: String?,
            eventTypeIn: Set<String>?,
            fromTime: Instant?,
            toTime: Instant?,
            page: Int,
            size: Int,
        ): AuditLogQueryPort.SearchResult {
            lastFreeText = freeText
            lastEventTypeIn = eventTypeIn
            lastFromTime = fromTime
            lastToTime = toTime
            lastPage = page
            lastSize = size
            return super.search(freeText, eventTypeIn, fromTime, toTime, page, size)
        }
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }

    @Suppress("unused")
    private fun forceAuditEventTypeReference() {
        // Compile-time guard: ensure AuditEventType resolves.
        require(AuditEventType.DASHBOARD_OBSERVED.isNotBlank())
    }
}
