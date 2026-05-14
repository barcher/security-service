package com.shared.security.application.ports

/**
 * Verifies that the offsite KEK backup is readable + decrypts a known probe blob.
 *
 * Per proposal §8.5, every KEK that enters PRIOR status is mirrored to an offsite secret
 * store (HSM, cloud KMS, encrypted bucket). This port checks daily that the backup is
 * intact — a corrupt backup combined with a lost primary KEK would render every DEK bound
 * to it permanently unrecoverable, so we want detection at hour-scale not month-scale.
 *
 * Stream C ships behind `NoOpKekBackupVerifier`. The real verifier (which depends on
 * vendor selection for the backup store) arrives in Stream E or a follow-on.
 */
fun interface KekBackupVerifierPort {
    suspend fun verify(): VerifyResult

    sealed interface VerifyResult {
        /** Backup decrypted the probe successfully. */
        data class Ok(val backupKekId: String) : VerifyResult

        /** Backup was readable but the probe blob did not decrypt. */
        data class CorruptBackup(val backupKekId: String, val reason: String) : VerifyResult

        /** Backup store was unreachable. Use case should retry on next tick. */
        data class TransientFailure(val reason: String) : VerifyResult
    }
}
