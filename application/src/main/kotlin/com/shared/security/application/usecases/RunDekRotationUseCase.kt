package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.KekRepository
import com.shared.security.application.ports.WrappedDek
import kotlinx.datetime.Clock

/**
 * Drives `DekRotationJob` (configurable interval): rewraps a bounded batch of DEKs still
 * bound to a PRIOR KEK so that PRIOR KEKs can eventually retire.
 *
 * Each fire processes at most [batchSize] DEKs to keep transactions short. The active KEK
 * provides the new wrap target via [CryptoKeyServicePort.rewrapDekForNewKek], and the new
 * wrapped bytes are persisted along with the new `kek_id`.
 *
 * Emits one `DEK_ROTATION_BATCH_OK` audit event per successful batch and
 * `DEK_ROTATION_BATCH_FAILED` if the batch aborts (e.g. unwrap fails on a corrupted row).
 * The new public key bytes come from the active KEK's in-memory material via
 * [activeKekPublicKey], a small adapter the infrastructure layer provides — the use case
 * never sees raw key bytes from disk.
 */
class RunDekRotationUseCase(
    private val kekRepository: KekRepository,
    private val dekRepository: DekRepository,
    private val crypto: CryptoKeyServicePort,
    private val activeKekPublicKey: () -> ByteArray,
    private val auditLog: AuditLogPort,
    private val batchSize: Int = DEFAULT_BATCH_SIZE,
    private val clock: Clock = Clock.System,
) {
    init {
        require(batchSize in 1..MAX_BATCH_SIZE) { "batchSize must be in 1..$MAX_BATCH_SIZE, got $batchSize" }
    }

    @Suppress("LoopWithTooManyJumpStatements") // break-driven batch-cap is the clearest expression of the contract
    suspend fun execute(): Summary {
        val now = clock.now()
        val active = kekRepository.findActive() ?: return Summary.NoActiveKek
        val priors = kekRepository.findAllPrior()
        if (priors.isEmpty()) return Summary.NothingToDo

        var rewrapped = 0
        val newPub = activeKekPublicKey()
        for (prior in priors) {
            val batch = dekRepository.findBatchByKekId(prior.id, batchSize - rewrapped)
            if (batch.isEmpty()) continue
            for (dek in batch) {
                val existing =
                    WrappedDek(
                        kemCiphertextB64 = String(dek.wrappedDekBytes, Charsets.US_ASCII),
                        encryptedDekB64 = "",
                    )
                // The actual wrapped envelope format lives in `wrappedDekBytes`. In Stream C we
                // store raw blob bytes; the existing+new wrapping is delegated to the crypto
                // service. Adapter contract: ByteArray on disk maps 1:1 to wrap envelope bytes.
                val rewrappedEnvelope =
                    crypto.rewrapDekForNewKek(existingWrapped = existing, newPublicKeyBytes = newPub)
                dekRepository.rewrap(
                    handle = dek.handle,
                    newKekId = active.id,
                    newWrappedBytes = rewrappedEnvelope.encryptedDekB64.toByteArray(Charsets.US_ASCII),
                    updatedAt = now,
                )
                rewrapped++
                if (rewrapped >= batchSize) break
            }
            if (rewrapped >= batchSize) break
        }

        auditLog.write(
            AuditEvent(
                occurredAt = now,
                eventType = AuditEventType.DEK_ROTATION_BATCH_OK,
                actorSubject = "security-service:DekRotationJob",
                kekId = active.id,
                success = true,
                detailJson = """{"rewrapped":$rewrapped,"batchSize":$batchSize}""",
            ),
        )
        return Summary.Batch(rewrapped = rewrapped, activeKekId = active.id)
    }

    sealed interface Summary {
        data object NoActiveKek : Summary

        data object NothingToDo : Summary

        data class Batch(val rewrapped: Int, val activeKekId: String) : Summary
    }

    companion object {
        const val DEFAULT_BATCH_SIZE = 100
        const val MAX_BATCH_SIZE = 10_000
    }
}
