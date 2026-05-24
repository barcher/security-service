package com.shared.security.application.ports

import kotlinx.datetime.Instant

/**
 * Read/write surface over `deks` rows.
 *
 * `DekRotationJob` reads a bounded batch of DEKs bound to a PRIOR KEK, rewraps each under
 * the active KEK via `CryptoKeyServicePort.rewrapDekForNewKek`, and persists the new
 * wrapped bytes back through this port.
 */
interface DekRepository {
    /** Count of DEKs currently bound to [kekId]. Used by `KekPriorTtlJob` to decide retire-eligibility. */
    suspend fun countByKekId(kekId: String): Long

    /** A bounded batch of DEKs still referencing [kekId], oldest first. */
    suspend fun findBatchByKekId(
        kekId: String,
        limit: Int,
    ): List<DekRecord>

    /**
     * Move [handle] from its current `kek_id` + `wrapped_dek_bytes` to a new
     * (`newKekId`, `newWrappedBytes`) pair. Returns true on success, false when the DEK
     * is no longer present (already-deleted race).
     */
    suspend fun rewrap(
        handle: ByteArray,
        newKekId: String,
        newWrappedBytes: ByteArray,
        updatedAt: Instant,
    ): Boolean

    /**
     * A bounded slice of DEK rows ordered by `created_at` desc. Used by the Stream L
     * observability surface for the dashboard. The returned [DekRecord] still carries
     * `wrappedDekBytes`; the observation use case strips that field before serializing.
     */
    suspend fun findRecent(limit: Int): List<DekRecord>

    /** Total count of DEK rows. Used by the observation surface for the dashboard count. */
    suspend fun countAll(): Long
}

data class DekRecord(
    val handle: ByteArray,
    val kekId: String,
    val wrappedDekBytes: ByteArray,
    val createdAt: Instant,
    val updatedAt: Instant,
) {
    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}
