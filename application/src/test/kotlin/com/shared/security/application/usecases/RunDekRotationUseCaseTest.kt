package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.KekLifecycleStatus
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RunDekRotationUseCaseTest {
    private val fixedClock =
        object : Clock {
            override fun now() = Instant.fromEpochMilliseconds(1_000_000)
        }
    private val pubBytes = ByteArray(64) { 9 }

    @Test
    fun `no ACTIVE KEK yields NoActiveKek and writes no audit`() =
        runTest {
            val useCase =
                RunDekRotationUseCase(
                    FakeKekRepository(),
                    FakeDekRepository(),
                    FlakyCryptoKeyService(),
                    activeKekPublicKey = { pubBytes },
                    auditLog = RecordingAuditLog(),
                    clock = fixedClock,
                )

            val summary = useCase.execute()

            assertEquals(RunDekRotationUseCase.Summary.NoActiveKek, summary)
        }

    @Test
    fun `no PRIOR KEKs yields NothingToDo`() =
        runTest {
            val kekRepo = FakeKekRepository()
            kekRepo.seed(KekLifecycleStatus.ACTIVE)
            val useCase =
                RunDekRotationUseCase(
                    kekRepo,
                    FakeDekRepository(),
                    FlakyCryptoKeyService(),
                    activeKekPublicKey = { pubBytes },
                    auditLog = RecordingAuditLog(),
                    clock = fixedClock,
                )

            assertEquals(RunDekRotationUseCase.Summary.NothingToDo, useCase.execute())
        }

    @Test
    fun `rewraps DEKs bound to PRIOR KEKs up to the batch cap`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            val crypto = FlakyCryptoKeyService()
            val activeId = kekRepo.seed(KekLifecycleStatus.ACTIVE)
            val priorId = kekRepo.seed(KekLifecycleStatus.PRIOR)
            dekRepo.seed(kekId = priorId, count = 10)

            val useCase =
                RunDekRotationUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    crypto = crypto,
                    activeKekPublicKey = { pubBytes },
                    auditLog = audit,
                    batchSize = 4,
                    clock = fixedClock,
                )

            val summary = useCase.execute()

            assertTrue(summary is RunDekRotationUseCase.Summary.Batch)
            val batch = summary as RunDekRotationUseCase.Summary.Batch
            assertEquals(4, batch.rewrapped)
            assertEquals(activeId, batch.activeKekId)
            assertEquals(4, dekRepo.rewraps.size)
            dekRepo.rewraps.forEach { (_, newKekId, _) ->
                assertEquals(activeId, newKekId)
            }
        }

    @Test
    fun `rewrapped DEKs are reassigned to the active KEK in storage`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val activeId = kekRepo.seed(KekLifecycleStatus.ACTIVE)
            val priorId = kekRepo.seed(KekLifecycleStatus.PRIOR)
            dekRepo.seed(kekId = priorId, count = 2)

            val useCase =
                RunDekRotationUseCase(
                    kekRepository = kekRepo,
                    dekRepository = dekRepo,
                    crypto = FlakyCryptoKeyService(),
                    activeKekPublicKey = { pubBytes },
                    auditLog = RecordingAuditLog(),
                    batchSize = 5,
                    clock = fixedClock,
                )

            useCase.execute()

            assertEquals(0L, dekRepo.countByKekId(priorId))
            assertEquals(2L, dekRepo.countByKekId(activeId))
        }

    @Test
    fun `emits DEK_ROTATION_BATCH_OK audit with rewrapped count`() =
        runTest {
            val kekRepo = FakeKekRepository()
            val dekRepo = FakeDekRepository()
            val audit = RecordingAuditLog()
            kekRepo.seed(KekLifecycleStatus.ACTIVE)
            val priorId = kekRepo.seed(KekLifecycleStatus.PRIOR)
            dekRepo.seed(kekId = priorId, count = 3)

            RunDekRotationUseCase(
                kekRepository = kekRepo,
                dekRepository = dekRepo,
                crypto = FlakyCryptoKeyService(),
                activeKekPublicKey = { pubBytes },
                auditLog = audit,
                batchSize = 5,
                clock = fixedClock,
            ).execute()

            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.DEK_ROTATION_BATCH_OK }
            assertNotNull(ev)
            assertTrue(ev!!.detailJson!!.contains("\"rewrapped\":3"))
        }

    @Test
    fun `constructor rejects out-of-range batch size`() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException::class.java) {
            RunDekRotationUseCase(
                kekRepository = FakeKekRepository(),
                dekRepository = FakeDekRepository(),
                crypto = FlakyCryptoKeyService(),
                activeKekPublicKey = { pubBytes },
                auditLog = RecordingAuditLog(),
                batchSize = 0,
            )
        }
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException::class.java) {
            RunDekRotationUseCase(
                kekRepository = FakeKekRepository(),
                dekRepository = FakeDekRepository(),
                crypto = FlakyCryptoKeyService(),
                activeKekPublicKey = { pubBytes },
                auditLog = RecordingAuditLog(),
                batchSize = 100_000,
            )
        }
    }
}
