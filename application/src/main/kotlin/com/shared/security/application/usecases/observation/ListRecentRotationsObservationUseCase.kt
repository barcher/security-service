package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import kotlinx.datetime.Clock

/**
 * Stream L L.0 (SKS-L07) — convenience query: the last N audit rows whose `event_type`
 * is one of the rotation-relevant lifecycle events. The dashboard renders this as a
 * "Recent rotations" sparkline / table next to the KEK + JWT-key panels.
 *
 * The filter set is hard-coded in the use case so the dashboard cannot smuggle in
 * arbitrary event types via this endpoint — a leaked observer cert can still query the
 * full search endpoint (L06) but this convenience endpoint surfaces only rotation events.
 *
 * **Audit:** ONE [AuditEventType.DASHBOARD_OBSERVED] per call.
 */
class ListRecentRotationsObservationUseCase(
    private val queryPort: AuditLogQueryPort,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(
        actorSubject: String?,
        n: Int = DEFAULT_N,
    ): List<RotationObservation> {
        require(n > 0) { "n must be positive, was $n" }
        val effectiveN = n.coerceAtMost(MAX_N)
        val result =
            queryPort.search(
                eventTypeIn = ROTATION_EVENT_TYPES,
                page = 0,
                size = effectiveN,
            )
        auditLog.write(
            AuditEvent(
                occurredAt = clock.now(),
                eventType = AuditEventType.DASHBOARD_OBSERVED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"resource":"recent-rotations","rowCount":${result.rows.size}}""",
            ),
        )
        return result.rows.map { row ->
            RotationObservation(
                id = row.id,
                occurredAt = row.occurredAt,
                eventType = row.eventType,
                actorSubject = row.actorSubject,
                kekId = row.kekId,
                detailJson = row.detailJson,
            )
        }
    }

    companion object {
        const val DEFAULT_N: Int = 20
        const val MAX_N: Int = 100

        /** The locked filter — only these event types are surfaced via this endpoint. */
        val ROTATION_EVENT_TYPES: Set<String> =
            setOf(
                AuditEventType.KEK_ACTIVATED,
                AuditEventType.KEK_RETIRED,
                AuditEventType.DEK_ROTATION_BATCH_OK,
                AuditEventType.JWKS_KEY_ACTIVATED,
                AuditEventType.JWKS_KEY_RETIRED,
            )
    }
}
