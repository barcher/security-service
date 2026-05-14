package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditBatch
import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.ColdStoragePort
import com.shared.security.application.ports.ShipResult
import kotlinx.datetime.Clock
import java.util.UUID

/**
 * Drives `AuditLogShipperJob` (hourly): verifies the chain over the new tail and ships a
 * contiguous batch of audit rows to immutable cold storage.
 *
 * Stream C scope: the chain-builder and batch reader are injected as suspending functions
 * so the use case stays storage-agnostic. The persistent ExposedAuditLogRepository has its
 * own `verifyChain` method (`SKS-C05`); the lambda wiring at the composition root passes
 * through to it.
 *
 * Failure modes:
 * - **CHAIN_BREAK** is structural tamper evidence — the use case emits `AUDIT_CHAIN_BREAK`,
 *   does NOT ship, and aborts. Operator intervention is required.
 * - **TransientFailure** on ship — emits no audit (the next tick retries).
 * - **PermanentFailure** on ship — emits an `AUDIT_SHIPPED` row with `success=false`.
 */
class RunAuditLogShipperUseCase(
    private val chainVerifier: suspend (fromId: Long, toId: Long) -> ChainVerification,
    private val batchReader: suspend (fromId: Long, toId: Long) -> AuditBatch,
    private val coldStorage: ColdStoragePort,
    private val auditLog: AuditLogPort,
    private val lastShippedIdProvider: suspend () -> Long,
    private val lastShippedIdSaver: suspend (Long) -> Unit,
    private val maxRowsPerBatch: Int = DEFAULT_MAX_ROWS,
    private val clock: Clock = Clock.System,
) {
    init {
        require(maxRowsPerBatch in 1..MAX_ROWS_PER_BATCH) {
            "maxRowsPerBatch must be 1..$MAX_ROWS_PER_BATCH"
        }
    }

    suspend fun execute(): Summary {
        val lastShipped = lastShippedIdProvider()
        val fromId = lastShipped + 1
        val toId = fromId + maxRowsPerBatch - 1

        val verification = chainVerifier(fromId, toId)
        if (verification is ChainVerification.Broken) {
            auditLog.write(
                AuditEvent(
                    occurredAt = clock.now(),
                    eventType = AuditEventType.AUDIT_CHAIN_BREAK,
                    actorSubject = "security-service:AuditLogShipperJob",
                    success = false,
                    detailJson = """{"firstBadId":${verification.firstBadId}}""",
                ),
            )
            return Summary.ChainBroken(verification.firstBadId)
        }
        if (verification is ChainVerification.Empty) return Summary.NothingToShip

        val batch = batchReader(fromId, toId)
        if (batch.toRowId < batch.fromRowId) return Summary.NothingToShip

        return when (val result = coldStorage.ship(batch)) {
            is ShipResult.Ok -> {
                lastShippedIdSaver(batch.toRowId)
                val from = batch.fromRowId
                val to = batch.toRowId
                val detail = """{"from":$from,"to":$to,"remote":"${result.remoteObjectKey}"}"""
                auditLog.write(
                    AuditEvent(
                        occurredAt = clock.now(),
                        eventType = AuditEventType.AUDIT_SHIPPED,
                        actorSubject = "security-service:AuditLogShipperJob",
                        success = true,
                        detailJson = detail,
                    ),
                )
                Summary.Shipped(fromRowId = from, toRowId = to)
            }
            is ShipResult.TransientFailure -> Summary.TransientFailure(result.message)
            is ShipResult.PermanentFailure -> {
                auditLog.write(
                    AuditEvent(
                        occurredAt = clock.now(),
                        eventType = AuditEventType.AUDIT_SHIPPED,
                        actorSubject = "security-service:AuditLogShipperJob",
                        success = false,
                        detailJson = """{"reason":"permanent_failure","message":"${result.message}"}""",
                    ),
                )
                Summary.PermanentFailure(result.message)
            }
        }
    }

    /** Result of verifying a slice of the audit chain. */
    sealed interface ChainVerification {
        data object Ok : ChainVerification

        data object Empty : ChainVerification

        data class Broken(val firstBadId: Long) : ChainVerification
    }

    sealed interface Summary {
        data class Shipped(val fromRowId: Long, val toRowId: Long) : Summary

        data object NothingToShip : Summary

        data class ChainBroken(val firstBadId: Long) : Summary

        data class TransientFailure(val message: String) : Summary

        data class PermanentFailure(val message: String) : Summary
    }

    companion object {
        const val DEFAULT_MAX_ROWS = 1000
        const val MAX_ROWS_PER_BATCH = 100_000

        /** Helper for adapters that need to mint a unique batch id. */
        fun mintBatchId(): String = UUID.randomUUID().toString()
    }
}
