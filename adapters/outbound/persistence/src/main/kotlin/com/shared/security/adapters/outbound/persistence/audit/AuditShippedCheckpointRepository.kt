package com.shared.security.adapters.outbound.persistence.audit

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update

/**
 * Stream C follow-up SHIP-02 — read/write surface over the single-row
 * `audit_shipped_checkpoint` table. Used by:
 *
 *   * `RunAuditLogShipperUseCase` — reads the checkpoint to know where to resume, writes
 *     after a successful batch ships.
 *   * `RunAuditRetentionUseCase` — reads the checkpoint to bound the delete by max id
 *     (never delete rows the shipper hasn't yet processed).
 *
 * Both reads + writes are single-row queries; this repository does not need a row lock
 * because the scheduler serialises the shipper + retention jobs (they share a job group
 * and Quartz does not fire them concurrently on a single instance).
 */
class AuditShippedCheckpointRepository(private val database: Database) {
    suspend fun load(): Long =
        withContext(Dispatchers.IO) {
            transaction(database) {
                AuditShippedCheckpointTable.selectAll()
                    .where { AuditShippedCheckpointTable.id eq SINGLETON_ID }
                    .firstOrNull()
                    ?.get(AuditShippedCheckpointTable.lastShippedId)
                    ?: 0L
            }
        }

    suspend fun save(value: Long) {
        withContext(Dispatchers.IO) {
            transaction(database) {
                AuditShippedCheckpointTable.update({ AuditShippedCheckpointTable.id eq SINGLETON_ID }) {
                    it[lastShippedId] = value
                    it[updatedAt] = Clock.System.now()
                }
            }
        }
    }

    private companion object {
        private const val SINGLETON_ID: Byte = 1
    }
}
