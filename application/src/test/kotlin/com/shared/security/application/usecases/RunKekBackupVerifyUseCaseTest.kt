package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.KekBackupVerifierPort
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RunKekBackupVerifyUseCaseTest {
    @Test
    fun `Ok verification writes KEK_BACKUP_VERIFIED success true`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunKekBackupVerifyUseCase(
                    verifier = KekBackupVerifierPort { KekBackupVerifierPort.VerifyResult.Ok("backup-1") },
                    auditLog = audit,
                )

            val summary = useCase.execute()

            assertTrue(summary is RunKekBackupVerifyUseCase.Summary.Verified)
            assertEquals("backup-1", (summary as RunKekBackupVerifyUseCase.Summary.Verified).backupKekId)
            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.KEK_BACKUP_VERIFIED }
            assertNotNull(ev)
            assertTrue(ev!!.detailJson!!.contains("backup-1"))
            assertEquals(true, ev.success)
        }

    @Test
    fun `CorruptBackup writes KEK_BACKUP_VERIFY_FAILED success false`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunKekBackupVerifyUseCase(
                    verifier =
                        KekBackupVerifierPort {
                            KekBackupVerifierPort.VerifyResult.CorruptBackup("backup-2", "bad MAC")
                        },
                    auditLog = audit,
                )

            useCase.execute()

            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.KEK_BACKUP_VERIFY_FAILED }
            assertNotNull(ev)
            assertEquals(false, ev!!.success)
            assertTrue(ev.detailJson!!.contains("bad MAC"))
        }

    @Test
    fun `TransientFailure writes no audit and yields TransientFailure summary`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunKekBackupVerifyUseCase(
                    verifier =
                        KekBackupVerifierPort {
                            KekBackupVerifierPort.VerifyResult.TransientFailure("network timeout")
                        },
                    auditLog = audit,
                )

            val summary = useCase.execute()

            assertTrue(summary is RunKekBackupVerifyUseCase.Summary.TransientFailure)
            assertEquals(0, audit.events.size)
        }
}
