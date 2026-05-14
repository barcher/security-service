package com.shared.security.infrastructure.kek

import com.shared.security.application.ports.KekBackupVerifierPort
import org.slf4j.LoggerFactory

/**
 * Stream-C placeholder backup verifier. Returns `Ok` with a synthetic backup-kek id. The
 * real verifier (which depends on vendor selection for the backup secret store) arrives
 * in Stream E or as a follow-on.
 *
 * Until a real verifier is wired, daily fires write `KEK_BACKUP_VERIFIED` audit events with
 * `success=true` — a clear signal in the audit log that backup verification has not been
 * implemented for the current deployment.
 */
class NoOpKekBackupVerifier : KekBackupVerifierPort {
    private val logger = LoggerFactory.getLogger(NoOpKekBackupVerifier::class.java)

    override suspend fun verify(): KekBackupVerifierPort.VerifyResult {
        logger.warn("NoOpKekBackupVerifier.verify: no real backup-store adapter wired — returning synthetic Ok")
        return KekBackupVerifierPort.VerifyResult.Ok(backupKekId = "noop:not-configured")
    }
}
