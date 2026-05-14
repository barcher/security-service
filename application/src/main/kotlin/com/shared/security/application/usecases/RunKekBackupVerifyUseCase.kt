package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.KekBackupVerifierPort
import kotlinx.datetime.Clock

/**
 * Drives `KekBackupVerifyJob` (daily): asks the backup-verifier port to attempt a probe
 * decrypt against the offsite KEK backup. Emits one audit event per fire:
 *
 *   - `KEK_BACKUP_VERIFIED` (success=true) on Ok
 *   - `KEK_BACKUP_VERIFY_FAILED` (success=false) on CorruptBackup
 *   - no audit on TransientFailure — the next tick retries
 *
 * Per proposal §8.5, this is the operational guard that catches "lost both primary and
 * backup" before it becomes unrecoverable. The verifier itself is a port; Stream C ships
 * a NoOp implementation and Stream E wires the real adapter once the backup-store vendor
 * is picked.
 */
class RunKekBackupVerifyUseCase(
    private val verifier: KekBackupVerifierPort,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(): Summary {
        val now = clock.now()
        return when (val result = verifier.verify()) {
            is KekBackupVerifierPort.VerifyResult.Ok -> {
                auditLog.write(
                    AuditEvent(
                        occurredAt = now,
                        eventType = AuditEventType.KEK_BACKUP_VERIFIED,
                        actorSubject = "security-service:KekBackupVerifyJob",
                        success = true,
                        detailJson = """{"backupKekId":"${result.backupKekId}"}""",
                    ),
                )
                Summary.Verified(result.backupKekId)
            }
            is KekBackupVerifierPort.VerifyResult.CorruptBackup -> {
                auditLog.write(
                    AuditEvent(
                        occurredAt = now,
                        eventType = AuditEventType.KEK_BACKUP_VERIFY_FAILED,
                        actorSubject = "security-service:KekBackupVerifyJob",
                        success = false,
                        detailJson = """{"backupKekId":"${result.backupKekId}","reason":"${result.reason}"}""",
                    ),
                )
                Summary.Corrupt(result.backupKekId, result.reason)
            }
            is KekBackupVerifierPort.VerifyResult.TransientFailure -> Summary.TransientFailure(result.reason)
        }
    }

    sealed interface Summary {
        data class Verified(val backupKekId: String) : Summary

        data class Corrupt(val backupKekId: String, val reason: String) : Summary

        data class TransientFailure(val reason: String) : Summary
    }
}
