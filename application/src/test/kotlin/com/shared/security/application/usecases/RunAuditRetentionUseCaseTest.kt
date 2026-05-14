package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEventType
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.days

class RunAuditRetentionUseCaseTest {
    private fun clockAt(epochMillis: Long) =
        object : Clock {
            override fun now() = Instant.fromEpochMilliseconds(epochMillis)
        }

    @Test
    fun `nothing-shipped-yet short-circuits without calling deleter`() =
        runTest {
            val audit = RecordingAuditLog()
            var deleterCalled = false
            val useCase =
                RunAuditRetentionUseCase(
                    deleter = { _, _ ->
                        deleterCalled = true
                        0L
                    },
                    lastShippedIdProvider = { 0L },
                    auditLog = audit,
                    retentionDuration = 2555.days,
                    clock = clockAt(Long.MAX_VALUE / 4),
                )

            assertEquals(RunAuditRetentionUseCase.Summary.NothingShippedYet, useCase.execute())
            assertEquals(false, deleterCalled)
            assertEquals(0, audit.events.size)
        }

    @Test
    fun `delete count above zero writes AUDIT_RETENTION_DELETED audit`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunAuditRetentionUseCase(
                    deleter = { _, _ -> 42L },
                    lastShippedIdProvider = { 100L },
                    auditLog = audit,
                    retentionDuration = 365.days,
                    clock = clockAt(1_000_000_000),
                )

            val summary = useCase.execute()

            assertEquals(RunAuditRetentionUseCase.Summary.Deleted(42L), summary)
            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.AUDIT_RETENTION_DELETED }
            assertEquals(true, ev?.success)
            assertTrue(ev!!.detailJson!!.contains("\"deleted\":42"))
        }

    @Test
    fun `zero-delete fires no audit event`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunAuditRetentionUseCase(
                    deleter = { _, _ -> 0L },
                    lastShippedIdProvider = { 100L },
                    auditLog = audit,
                    retentionDuration = 365.days,
                )

            assertEquals(RunAuditRetentionUseCase.Summary.Deleted(0L), useCase.execute())
            assertEquals(0, audit.events.size)
        }

    @Test
    fun `deleter is bounded by lastShippedId not by clock cutoff alone`() =
        runTest {
            var deleterMaxId = -1L
            val useCase =
                RunAuditRetentionUseCase(
                    deleter = { _, maxId ->
                        deleterMaxId = maxId
                        0L
                    },
                    lastShippedIdProvider = { 555L },
                    auditLog = RecordingAuditLog(),
                    retentionDuration = 365.days,
                )

            useCase.execute()

            assertEquals(555L, deleterMaxId)
        }
}
