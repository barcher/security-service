package com.shared.security.application.ports

import kotlinx.datetime.Instant

/**
 * Read/write surface over `keks` rows for the KEK lifecycle state machine.
 *
 * Stream C use cases (`RunKekHealthCheckUseCase`, `RunKekPriorTtlUseCase`,
 * `RunDekRotationUseCase`) drive transitions through this port. The port returns plain
 * value types so application code is unaware of Exposed.
 */
interface KekRepository {
    /** Currently ACTIVE KEK, or null when none. Schema guarantees at most one row. */
    suspend fun findActive(): KekRecord?

    /** All KEKs in PRIOR status, oldest first. */
    suspend fun findAllPrior(): List<KekRecord>

    /** Look up by primary-key id. */
    suspend fun findById(id: String): KekRecord?

    /** Transition [id] from PRIOR to RETIRED. Sets `retired_at = now`. */
    suspend fun retirePrior(id: String): Boolean
}

/**
 * One row in the `keks` table. KEK *bytes* are intentionally NOT here — those live in
 * memory only (loaded by `KekProviderPort` from a mounted secret). This record carries only
 * metadata safe to display in audit + admin contexts.
 */
data class KekRecord(
    val id: String,
    val fingerprint: String,
    val status: KekLifecycleStatus,
    val createdAt: Instant,
    val activatedAt: Instant?,
    val quiescedAt: Instant?,
    val retiredAt: Instant?,
)

enum class KekLifecycleStatus {
    STAGED,
    ACTIVE,
    PRIOR,
    RETIRED,
}
