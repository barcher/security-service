package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Stream L L.0 (SKS-L06) — paginated faceted search over `audit_events`. The dashboard's
 * "Crypto-ops" audit-log tab is the primary consumer.
 *
 * **Pagination:** 0-based pages. Default size 50, capped at 200 (mirrors the monolith's
 * own audit search). The cap is the only structural guardrail against a runaway dashboard
 * query — combined with the per-subject rate limit on `/v1/observability/audit-events`,
 * a misbehaving dashboard can degrade itself but not the security service.
 *
 * **Strips `prev_hmac` and `row_hmac`** at the query port boundary (those columns are
 * persistence-internal and never leave the persistence module). The use case adds no
 * further stripping but maps to a stable wire DTO.
 *
 * **Audit:** ONE [AuditEventType.DASHBOARD_OBSERVED] per call regardless of page size or
 * total result count.
 */
class SearchAuditEventsObservationUseCase(
    private val queryPort: AuditLogQueryPort,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(
        actorSubject: String?,
        freeText: String? = null,
        eventTypeIn: Set<String>? = null,
        fromTime: Instant? = null,
        toTime: Instant? = null,
        page: Int = 0,
        size: Int = DEFAULT_PAGE_SIZE,
    ): AuditObservationPage {
        require(page >= 0) { "page must be non-negative, was $page" }
        val effectiveSize = size.coerceIn(1, MAX_PAGE_SIZE)
        val result =
            queryPort.search(
                freeText = freeText,
                eventTypeIn = eventTypeIn,
                fromTime = fromTime,
                toTime = toTime,
                page = page,
                size = effectiveSize,
            )
        auditLog.write(
            AuditEvent(
                occurredAt = clock.now(),
                eventType = AuditEventType.DASHBOARD_OBSERVED,
                actorSubject = actorSubject,
                success = true,
                detailJson =
                    """{"resource":"audit-events","rowCount":${result.rows.size},""" +
                        """"totalCount":${result.totalCount},"page":$page,"size":$effectiveSize}""",
            ),
        )
        return AuditObservationPage(
            items =
                result.rows.map { row ->
                    AuditObservation(
                        id = row.id,
                        occurredAt = row.occurredAt,
                        eventType = row.eventType,
                        actorSubject = row.actorSubject,
                        kekId = row.kekId,
                        dekHandleHex = row.dekHandle?.joinToString("") { "%02x".format(it) },
                        success = row.success,
                        detailJson = row.detailJson,
                    )
                },
            totalCount = result.totalCount,
            page = page,
            pageSize = effectiveSize,
        )
    }

    companion object {
        const val DEFAULT_PAGE_SIZE: Int = 50
        const val MAX_PAGE_SIZE: Int = 200
    }
}
