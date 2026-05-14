package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.KekLifecycleStatus
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.hours

class RunKekPriorTtlUseCaseTest {
    private fun clockAt(epochMillis: Long) =
        object : Clock {
            override fun now() = Instant.fromEpochMilliseconds(epochMillis)
        }

    @Test
    fun `PRIOR with no DEKs and TTL elapsed retires and writes KEK_RETIRED audit`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            val oneDay = 24L * 60 * 60 * 1000
            val priorId = kekRepo.seed(KekLifecycleStatus.PRIOR, quiescedAt = Instant.fromEpochMilliseconds(0))

            val useCase =
                RunKekPriorTtlUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    auditLog = audit,
                    quiesceWindow = 24.hours,
                    clock = clockAt(oneDay),
                )

            val summary = useCase.execute()

            assertEquals(1, summary.retired)
            assertEquals(0, summary.blockedByDeks)
            assertEquals(0, summary.blockedByTtl)
            assertEquals(KekLifecycleStatus.RETIRED, kekRepo.byId[priorId]!!.status)
            val retiredEvent = audit.events.firstOrNull { it.eventType == AuditEventType.KEK_RETIRED }
            assertNotNull(retiredEvent)
            assertEquals(priorId, retiredEvent!!.kekId)
        }

    @Test
    fun `PRIOR with live DEKs stays PRIOR even when TTL has elapsed`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            val priorId = kekRepo.seed(KekLifecycleStatus.PRIOR, quiescedAt = Instant.fromEpochMilliseconds(0))
            dekRepo.seed(kekId = priorId, count = 3)

            val useCase =
                RunKekPriorTtlUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    auditLog = audit,
                    quiesceWindow = 24.hours,
                    clock = clockAt(48L * 3600 * 1000),
                )

            val summary = useCase.execute()

            assertEquals(0, summary.retired)
            assertEquals(1, summary.blockedByDeks)
            assertEquals(KekLifecycleStatus.PRIOR, kekRepo.byId[priorId]!!.status)
        }

    @Test
    fun `PRIOR within TTL window stays PRIOR even when no DEKs remain`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            kekRepo.seed(KekLifecycleStatus.PRIOR, quiescedAt = Instant.fromEpochMilliseconds(0))

            val useCase =
                RunKekPriorTtlUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    auditLog = audit,
                    quiesceWindow = 24.hours,
                    clock = clockAt(1L * 3600 * 1000),
                )

            val summary = useCase.execute()

            assertEquals(0, summary.retired)
            assertEquals(1, summary.blockedByTtl)
        }

    @Test
    fun `PRIOR with null quiescedAt is treated as TTL-not-elapsed`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            kekRepo.seed(KekLifecycleStatus.PRIOR, quiescedAt = null)

            val useCase =
                RunKekPriorTtlUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    auditLog = audit,
                    quiesceWindow = 24.hours,
                    clock = clockAt(Long.MAX_VALUE / 2),
                )

            val summary = useCase.execute()

            assertEquals(1, summary.blockedByTtl)
            assertEquals(0, summary.retired)
        }

    @Test
    fun `no PRIOR rows yields zero candidates and zero audit events`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            kekRepo.seed(KekLifecycleStatus.ACTIVE)

            val useCase =
                RunKekPriorTtlUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    auditLog = audit,
                    quiesceWindow = 24.hours,
                    clock = clockAt(0),
                )

            val summary = useCase.execute()

            assertEquals(0, summary.candidatesEvaluated)
            assertEquals(0, audit.events.size)
        }
}
