package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEventType
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RunKekHealthCheckUseCaseTest {
    @Test
    fun `successful probe writes HEALTH_CHECK_OK with success true`() =
        runTest {
            val audit = RecordingAuditLog()
            val crypto = FlakyCryptoKeyService()
            val useCase = RunKekHealthCheckUseCase(crypto, audit)

            val result = useCase.execute()

            assertEquals(RunKekHealthCheckUseCase.Result.OK, result)
            assertEquals(1, audit.events.size)
            assertEquals(AuditEventType.HEALTH_CHECK_OK, audit.events.first().eventType)
            assertTrue(audit.events.first().success)
        }

    @Test
    fun `generate failure writes HEALTH_CHECK_FAILED with success false`() =
        runTest {
            val audit = RecordingAuditLog()
            val crypto = FlakyCryptoKeyService(failGenerate = true)
            val useCase = RunKekHealthCheckUseCase(crypto, audit)

            val result = useCase.execute()

            assertTrue(result is RunKekHealthCheckUseCase.Result.Failed)
            assertEquals(1, audit.events.size)
            assertEquals(AuditEventType.HEALTH_CHECK_FAILED, audit.events.first().eventType)
            assertEquals(false, audit.events.first().success)
        }

    @Test
    fun `unwrap failure writes HEALTH_CHECK_FAILED`() =
        runTest {
            val audit = RecordingAuditLog()
            val crypto = FlakyCryptoKeyService(failUnwrap = true)
            val useCase = RunKekHealthCheckUseCase(crypto, audit)

            useCase.execute()

            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.HEALTH_CHECK_FAILED }
            assertNotNull(ev)
            assertTrue(ev!!.detailJson!!.contains("IllegalStateException"))
        }

    @Test
    fun `actor subject defaults to the job name`() =
        runTest {
            val audit = RecordingAuditLog()
            val crypto = FlakyCryptoKeyService()
            val useCase = RunKekHealthCheckUseCase(crypto, audit)

            useCase.execute()

            assertEquals("security-service:KekRotationHealthJob", audit.events.first().actorSubject)
        }
}
