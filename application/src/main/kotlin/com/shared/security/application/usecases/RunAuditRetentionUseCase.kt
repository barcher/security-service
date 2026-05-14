package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration

/**
 * Drives `AuditRetentionJob` (daily): deletes audit rows older than [retentionDuration]
 * **only after** the cold-storage shipper has confirmed those rows are durably stored.
 *
 * The guard `lastShippedIdProvider() >= rowId` ensures no row is deleted before its cold
 * copy exists — a row's only safe-to-delete condition is `occurredAt < cutoff AND id <=
 * lastShippedId`. Failure to honour this would create an audit gap that breaks the chain.
 *
 * Default retention is 7 years (FedRAMP audit log retention floor per AU-11).
 */
class RunAuditRetentionUseCase(
    private val deleter: suspend (cutoff: Instant, maxId: Long) -> Long,
    private val lastShippedIdProvider: suspend () -> Long,
    private val auditLog: AuditLogPort,
    private val retentionDuration: Duration,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(): Summary {
        val now = clock.now()
        val cutoff = now - retentionDuration
        val lastShipped = lastShippedIdProvider()
        if (lastShipped <= 0) return Summary.NothingShippedYet

        val deleted = deleter(cutoff, lastShipped)
        if (deleted > 0) {
            auditLog.write(
                AuditEvent(
                    occurredAt = now,
                    eventType = AuditEventType.AUDIT_RETENTION_DELETED,
                    actorSubject = "security-service:AuditRetentionJob",
                    success = true,
                    detailJson = """{"deleted":$deleted,"cutoff":"$cutoff","maxId":$lastShipped}""",
                ),
            )
        }
        return Summary.Deleted(deleted)
    }

    sealed interface Summary {
        data class Deleted(val count: Long) : Summary

        data object NothingShippedYet : Summary
    }
}
