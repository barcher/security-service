package com.shared.security.adapters.outbound.persistence.audit

import com.shared.security.adapters.outbound.persistence.tables.AuditEventsTable
import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditLogPort
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SortOrder
import org.jetbrains.exposed.sql.SqlExpressionBuilder.greaterEq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.lessEq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction

/**
 * Persistent, HMAC-SHA-512 chained [AuditLogPort] backed by `audit_events`.
 *
 * Write protocol (within a single REPEATABLE_READ transaction):
 *
 *   1. `SELECT row_hmac FROM audit_events ORDER BY id DESC LIMIT 1 FOR UPDATE`
 *      — exclusive lock prevents concurrent writers from racing on `prev_hmac`.
 *   2. `prev_hmac := (lock result) ?: INITIAL_PREV_HMAC`
 *   3. `row_hmac := AuditChainHasher.hash(event, prev_hmac)`
 *   4. `INSERT ...`
 *
 * Verification reads the chain in id order and recomputes each row_hmac from
 * canonical_payload + prev_hmac. Any mismatch returns the first broken row id; callers
 * (AuditLogShipperJob, ad-hoc verification routes) treat that as a tamper indicator.
 *
 * **Why `FOR UPDATE` on the latest row rather than table-level lock:** the chain only needs
 * serialization on writers; concurrent reads of historical rows are unaffected. A
 * row-level lock on the latest row is the minimal serialization that still produces a
 * deterministic chain.
 */
class ExposedAuditLogRepository(
    private val database: Database,
    private val hasher: AuditChainHasher,
) : AuditLogPort {
    override suspend fun write(event: AuditEvent) {
        // Coroutine → blocking JDBC bridge: Exposed's `transaction { }` is blocking; isolate it
        // on the IO dispatcher so we do not pin the request-handling worker.
        withContext(Dispatchers.IO) {
            transaction(database) {
                val prev = lockAndReadLatestHmac() ?: AuditChainHasher.INITIAL_PREV_HMAC
                val row = hasher.hash(event, prev)
                AuditEventsTable.insert {
                    it[occurredAt] = event.occurredAt
                    it[eventType] = event.eventType
                    it[actorSubject] = event.actorSubject
                    it[dekHandle] = event.dekHandle
                    it[kekId] = event.kekId
                    it[success] = event.success
                    it[detailJson] = event.detailJson?.let { json -> Json.parseToJsonElement(json) }
                    it[prevHmac] = prev
                    it[rowHmac] = row
                }
            }
        }
    }

    /**
     * Verify the chain across `[fromId, toId]` (inclusive). Returns a result indicating
     * either success or the id of the first row whose recomputed `row_hmac` does not match
     * the stored value.
     */
    suspend fun verifyChain(
        fromId: Long = 1,
        toId: Long = Long.MAX_VALUE,
    ): VerifyResult =
        withContext(Dispatchers.IO) {
            transaction(database) {
                val rows =
                    AuditEventsTable
                        .selectAll()
                        .where { (AuditEventsTable.id greaterEq fromId) and (AuditEventsTable.id lessEq toId) }
                        .orderBy(AuditEventsTable.id to SortOrder.ASC)
                        .toList()

                if (rows.isEmpty()) return@transaction VerifyResult.EMPTY

                rows.forEachIndexed { index, row ->
                    val expectedPrev =
                        if (index == 0) {
                            row[AuditEventsTable.prevHmac]
                        } else {
                            rows[index - 1][AuditEventsTable.rowHmac]
                        }
                    if (!row[AuditEventsTable.prevHmac].contentEquals(expectedPrev)) {
                        return@transaction VerifyResult.brokenAt(row[AuditEventsTable.id])
                    }
                    val event = row.toAuditEvent()
                    val expectedRow = hasher.hash(event, expectedPrev)
                    if (!row[AuditEventsTable.rowHmac].contentEquals(expectedRow)) {
                        return@transaction VerifyResult.brokenAt(row[AuditEventsTable.id])
                    }
                }
                VerifyResult.OK
            }
        }

    private fun lockAndReadLatestHmac(): ByteArray? {
        val latest =
            AuditEventsTable
                .selectAll()
                .orderBy(AuditEventsTable.id to SortOrder.DESC)
                .limit(1)
                .forUpdate()
                .firstOrNull()
        return latest?.get(AuditEventsTable.rowHmac)
    }

    private fun org.jetbrains.exposed.sql.ResultRow.toAuditEvent(): AuditEvent =
        AuditEvent(
            occurredAt = this[AuditEventsTable.occurredAt],
            eventType = this[AuditEventsTable.eventType],
            actorSubject = this[AuditEventsTable.actorSubject],
            dekHandle = this[AuditEventsTable.dekHandle],
            kekId = this[AuditEventsTable.kekId],
            success = this[AuditEventsTable.success],
            detailJson = this[AuditEventsTable.detailJson]?.toString(),
        )

    sealed interface VerifyResult {
        data object OK : VerifyResult

        data object EMPTY : VerifyResult

        data class BrokenAt(val firstBadId: Long) : VerifyResult

        companion object {
            fun brokenAt(id: Long): VerifyResult = BrokenAt(id)
        }
    }
}
