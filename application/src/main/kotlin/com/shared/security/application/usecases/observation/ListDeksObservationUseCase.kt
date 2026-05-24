package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.DekRepository
import kotlinx.datetime.Clock

/**
 * Stream L L.0 (SKS-L04 half 2) — read-only DEK lifecycle view for the dashboard.
 *
 * Returns a bounded slice of the most recent DEKs plus the total count. The wrapped
 * DEK bytes from the underlying [com.shared.security.application.ports.DekRecord] are
 * STRIPPED here — the observation DTO carries only handle + KEK reference + timestamps.
 *
 * **Bounded result:** the dashboard surfaces a paginated view, but DEK rows can be
 * numerous (one per logical group encrypted). The default cap is intentionally small;
 * the dashboard's total-count display is what an operator uses to understand population
 * size, not the row list.
 *
 * **Audit:** ONE [AuditEventType.DASHBOARD_OBSERVED] row per call regardless of
 * `limit` or total population size.
 */
class ListDeksObservationUseCase(
    private val dekRepository: DekRepository,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(
        actorSubject: String?,
        limit: Int = DEFAULT_LIMIT,
    ): DekObservationPage {
        require(limit in 1..MAX_LIMIT) {
            "limit must be in 1..$MAX_LIMIT, was $limit"
        }
        val rows = dekRepository.findRecent(limit)
        val total = dekRepository.countAll()
        auditLog.write(
            AuditEvent(
                occurredAt = clock.now(),
                eventType = AuditEventType.DASHBOARD_OBSERVED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"resource":"deks","rowCount":${rows.size},"totalCount":$total}""",
            ),
        )
        return DekObservationPage(
            items =
                rows.map { rec ->
                    DekObservation(
                        handleHex = rec.handle.joinToString("") { "%02x".format(it) },
                        kekId = rec.kekId,
                        createdAt = rec.createdAt,
                        updatedAt = rec.updatedAt,
                    )
                },
            totalCount = total,
        )
    }

    companion object {
        const val DEFAULT_LIMIT: Int = 50
        const val MAX_LIMIT: Int = 200
    }
}
