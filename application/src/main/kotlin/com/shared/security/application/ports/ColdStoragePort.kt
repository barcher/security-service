package com.shared.security.application.ports

/**
 * Ships immutable audit log batches to an external append-only store (S3 / R2 / GCS).
 *
 * Stream C ships behind a `NoOpColdStorageAdapter` — the use case path is fully exercised
 * but no bytes leave the process. A real S3/R2 adapter lands in Stream E or as a follow-on
 * once the operator picks a cold-storage vendor.
 *
 * Contract:
 * - Implementations MUST be idempotent on retry — re-shipping the same [batchId] is a no-op.
 * - Implementations MUST NOT mutate the audit log.
 * - Implementations MUST report success only when the bytes are durably stored remotely.
 */
fun interface ColdStoragePort {
    suspend fun ship(batch: AuditBatch): ShipResult
}

/**
 * A contiguous range of audit rows being shipped. The [bytesCanonical] is the canonical
 * serialization of every row (each row encoded as: `id ‖ canonical_payload ‖ prev_hmac ‖ row_hmac`).
 * Verification on the receiving side can replay the HMAC chain to confirm integrity.
 */
data class AuditBatch(
    val batchId: String,
    val fromRowId: Long,
    val toRowId: Long,
    val bytesCanonical: ByteArray,
) {
    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}

sealed interface ShipResult {
    /** Bytes are durably stored. The remote object's identifier is captured for audit. */
    data class Ok(val remoteObjectKey: String) : ShipResult

    /** Network/permission error. Use case should retry on next tick. */
    data class TransientFailure(val message: String) : ShipResult

    /** Permanent failure (bad credentials, bucket gone). Operator intervention required. */
    data class PermanentFailure(val message: String) : ShipResult
}
