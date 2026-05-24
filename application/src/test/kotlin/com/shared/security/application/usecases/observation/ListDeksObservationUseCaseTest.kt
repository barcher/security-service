package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.DekRecord
import com.shared.security.application.ports.DekRepository
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ListDeksObservationUseCaseTest {
    @Test
    fun `empty repository returns empty page with totalCount=0 and one audit row`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase = ListDeksObservationUseCase(StubDekRepo(emptyList()), audit)

            val page = useCase.execute(actorSubject = "CN=observer")

            assertTrue(page.items.isEmpty())
            assertEquals(0L, page.totalCount)
            assertEquals(AuditEventType.DASHBOARD_OBSERVED, audit.events.single().eventType)
        }

    @Test
    fun `handle is hex-encoded on the observation DTO`() =
        runTest {
            val now = Clock.System.now()
            val handle = byteArrayOf(0x01, 0x02, 0xab.toByte(), 0xcd.toByte())
            val records =
                listOf(
                    DekRecord(
                        handle = handle,
                        kekId = "kek-1",
                        wrappedDekBytes = ByteArray(0),
                        createdAt = now,
                        updatedAt = now,
                    ),
                )
            val useCase = ListDeksObservationUseCase(StubDekRepo(records), RecordingAuditLog())

            val page = useCase.execute(actorSubject = null)

            assertEquals(1, page.items.size)
            assertEquals("0102abcd", page.items.single().handleHex)
        }

    @Test
    fun `wrappedDekBytes is NEVER serialized into the observation DTO`() =
        runTest {
            val now = Clock.System.now()
            val sensitiveBytes = ByteArray(64) { it.toByte() }
            val records =
                listOf(
                    DekRecord(
                        handle = ByteArray(16),
                        kekId = "kek-1",
                        wrappedDekBytes = sensitiveBytes,
                        createdAt = now,
                        updatedAt = now,
                    ),
                )
            val useCase = ListDeksObservationUseCase(StubDekRepo(records), RecordingAuditLog())

            val page = useCase.execute(actorSubject = "CN=observer")

            // Structural: the DTO has no wrappedDekBytes field. The compile-time check above the
            // factory plus this runtime assertion together pin the invariant.
            val dto = page.items.single()
            val dtoFields = dto.javaClass.declaredFields.map { it.name }
            assertTrue(
                "wrappedDekBytes" !in dtoFields,
                "DekObservation must not expose wrappedDekBytes; found: $dtoFields",
            )
        }

    @Test
    fun `default limit caps at 50`() =
        runTest {
            val now = Clock.System.now()
            val records = (1..100).map { dek(it, now) }
            val repo = SpyingDekRepo(records)
            val useCase = ListDeksObservationUseCase(repo, RecordingAuditLog())

            useCase.execute(actorSubject = "CN=observer")

            assertEquals(50, repo.lastLimit)
        }

    @Test
    fun `explicit limit is honored up to MAX_LIMIT`() =
        runTest {
            val repo = SpyingDekRepo(emptyList())
            val useCase = ListDeksObservationUseCase(repo, RecordingAuditLog())

            useCase.execute(actorSubject = null, limit = ListDeksObservationUseCase.MAX_LIMIT)

            assertEquals(ListDeksObservationUseCase.MAX_LIMIT, repo.lastLimit)
        }

    @Test
    fun `limit beyond MAX_LIMIT raises IllegalArgumentException`() =
        runTest {
            val useCase = ListDeksObservationUseCase(StubDekRepo(emptyList()), RecordingAuditLog())
            val thrown =
                runCatching {
                    useCase.execute(actorSubject = null, limit = ListDeksObservationUseCase.MAX_LIMIT + 1)
                }.exceptionOrNull()
            assertTrue(thrown is IllegalArgumentException, "Expected IllegalArgumentException, got $thrown")
        }

    @Test
    fun `limit of zero raises IllegalArgumentException`() =
        runTest {
            val useCase = ListDeksObservationUseCase(StubDekRepo(emptyList()), RecordingAuditLog())
            val thrown = runCatching { useCase.execute(actorSubject = null, limit = 0) }.exceptionOrNull()
            assertTrue(thrown is IllegalArgumentException)
        }

    @Test
    fun `audit detailJson includes totalCount distinct from row count`() =
        runTest {
            val now = Clock.System.now()
            val records = (1..3).map { dek(it, now) }
            val repo =
                object : DekRepository {
                    override suspend fun countByKekId(kekId: String): Long = error("not used")

                    override suspend fun findBatchByKekId(
                        kekId: String,
                        limit: Int,
                    ): List<DekRecord> = error("not used")

                    override suspend fun rewrap(
                        handle: ByteArray,
                        newKekId: String,
                        newWrappedBytes: ByteArray,
                        updatedAt: Instant,
                    ): Boolean = error("not used")

                    override suspend fun findRecent(limit: Int): List<DekRecord> = records

                    // Total count > result list size to exercise the totalCount delta.
                    override suspend fun countAll(): Long = 1_000L
                }
            val audit = RecordingAuditLog()
            val useCase = ListDeksObservationUseCase(repo, audit)

            useCase.execute(actorSubject = null)

            val event = audit.events.single()
            assertTrue(event.detailJson!!.contains("\"rowCount\":3"))
            assertTrue(event.detailJson.contains("\"totalCount\":1000"))
        }

    private fun dek(
        i: Int,
        now: Instant,
    ): DekRecord =
        DekRecord(
            handle = ByteArray(16) { i.toByte() },
            kekId = "kek-1",
            wrappedDekBytes = ByteArray(0),
            createdAt = now,
            updatedAt = now,
        )

    private open class StubDekRepo(private val all: List<DekRecord>) : DekRepository {
        override suspend fun countByKekId(kekId: String): Long = error("not used")

        override suspend fun findBatchByKekId(
            kekId: String,
            limit: Int,
        ): List<DekRecord> = error("not used")

        override suspend fun rewrap(
            handle: ByteArray,
            newKekId: String,
            newWrappedBytes: ByteArray,
            updatedAt: Instant,
        ): Boolean = error("not used")

        override suspend fun findRecent(limit: Int): List<DekRecord> = all.take(limit)

        override suspend fun countAll(): Long = all.size.toLong()
    }

    private class SpyingDekRepo(all: List<DekRecord>) : StubDekRepo(all) {
        var lastLimit: Int = -1

        override suspend fun findRecent(limit: Int): List<DekRecord> {
            lastLimit = limit
            return super.findRecent(limit)
        }
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }
}
