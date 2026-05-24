package com.shared.security.adapters.outbound.persistence.audit

import com.shared.security.adapters.outbound.persistence.tables.AuditEventsTable
import com.shared.security.application.ports.AuditLogQueryPort
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.Op
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SortOrder
import org.jetbrains.exposed.sql.SqlExpressionBuilder.greaterEq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.inList
import org.jetbrains.exposed.sql.SqlExpressionBuilder.lessEq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.like
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.or
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction

/**
 * Read-side impl of [AuditLogQueryPort] for Stream L L.0. Does not implement
 * [com.shared.security.application.ports.AuditLogPort] — the write side keeps its
 * own impl (`ExposedAuditLogRepository`) so the HMAC chain mutation stays scoped to
 * that one class.
 *
 * Results strip `prev_hmac` + `row_hmac` — those columns are persistence-internal and
 * never leave this module via the query port.
 */
class ExposedAuditLogQueryRepository(
    private val database: Database,
) : AuditLogQueryPort {
    override suspend fun search(
        freeText: String?,
        eventTypeIn: Set<String>?,
        fromTime: Instant?,
        toTime: Instant?,
        page: Int,
        size: Int,
    ): AuditLogQueryPort.SearchResult {
        require(page >= 0) { "page must be non-negative, was $page" }
        val effectiveSize = size.coerceIn(1, MAX_PAGE_SIZE)
        return withContext(Dispatchers.IO) {
            transaction(database) {
                val predicate = buildPredicate(freeText, eventTypeIn, fromTime, toTime)
                val total =
                    if (predicate != null) {
                        AuditEventsTable.selectAll().where { predicate }.count()
                    } else {
                        AuditEventsTable.selectAll().count()
                    }
                val query =
                    if (predicate != null) {
                        AuditEventsTable.selectAll().where { predicate }
                    } else {
                        AuditEventsTable.selectAll()
                    }
                val rows =
                    query
                        .orderBy(AuditEventsTable.occurredAt to SortOrder.DESC)
                        .limit(effectiveSize)
                        .offset(page.toLong() * effectiveSize.toLong())
                        .map { it.toQueryRow() }
                AuditLogQueryPort.SearchResult(rows = rows, totalCount = total)
            }
        }
    }

    private fun buildPredicate(
        freeText: String?,
        eventTypeIn: Set<String>?,
        fromTime: Instant?,
        toTime: Instant?,
    ): Op<Boolean>? {
        var predicate: Op<Boolean>? = null

        if (!freeText.isNullOrBlank()) {
            val pattern = "%${freeText.trim()}%"
            val freeTextPredicate =
                (AuditEventsTable.eventType like pattern) or
                    (AuditEventsTable.actorSubject like pattern) or
                    (AuditEventsTable.kekId like pattern)
            predicate = predicate?.and(freeTextPredicate) ?: freeTextPredicate
        }
        if (!eventTypeIn.isNullOrEmpty()) {
            val inListPredicate = AuditEventsTable.eventType inList eventTypeIn.toList()
            predicate = predicate?.and(inListPredicate) ?: inListPredicate
        }
        if (fromTime != null) {
            val gePredicate = AuditEventsTable.occurredAt greaterEq fromTime
            predicate = predicate?.and(gePredicate) ?: gePredicate
        }
        if (toTime != null) {
            val lePredicate = AuditEventsTable.occurredAt lessEq toTime
            predicate = predicate?.and(lePredicate) ?: lePredicate
        }
        return predicate
    }

    private fun ResultRow.toQueryRow(): AuditLogQueryPort.Row =
        AuditLogQueryPort.Row(
            id = this[AuditEventsTable.id],
            occurredAt = this[AuditEventsTable.occurredAt],
            eventType = this[AuditEventsTable.eventType],
            actorSubject = this[AuditEventsTable.actorSubject],
            kekId = this[AuditEventsTable.kekId],
            dekHandle = this[AuditEventsTable.dekHandle],
            success = this[AuditEventsTable.success],
            detailJson = this[AuditEventsTable.detailJson]?.toString(),
        )

    private companion object {
        private const val MAX_PAGE_SIZE: Int = 200
    }
}
