package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.KekRepository
import kotlinx.datetime.Clock

/**
 * Stream L L.0 (SKS-L04 half 1) — read-only KEK lifecycle view for the dashboard.
 *
 * The result list strips no fields from [com.shared.security.application.ports.KekRecord]
 * (the record itself is already metadata-only — it carries fingerprint + lifecycle
 * timestamps, never key bytes). Mapping to [KekObservation] is mostly a rename so the
 * dashboard wire format stays decoupled from the persistence record shape.
 *
 * **Audit:** writes exactly ONE [AuditEventType.DASHBOARD_OBSERVED] row per call,
 * regardless of how many rows the underlying query returns. The observer-side rate
 * limiter is the primary cardinality control.
 */
class ListKeksObservationUseCase(
    private val kekRepository: KekRepository,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(actorSubject: String?): List<KekObservation> {
        val records = kekRepository.findAll()
        auditLog.write(
            AuditEvent(
                occurredAt = clock.now(),
                eventType = AuditEventType.DASHBOARD_OBSERVED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"resource":"keks","rowCount":${records.size}}""",
            ),
        )
        return records.map { rec ->
            KekObservation(
                id = rec.id,
                fingerprint = rec.fingerprint,
                status = rec.status.name,
                createdAt = rec.createdAt,
                activatedAt = rec.activatedAt,
                quiescedAt = rec.quiescedAt,
                retiredAt = rec.retiredAt,
            )
        }
    }
}
