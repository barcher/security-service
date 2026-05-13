package com.workautomations.security.application.usecases

import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditEventType
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.application.ports.CryptoKeyServicePort
import com.workautomations.security.application.ports.WrappedDek
import kotlinx.datetime.Clock

/**
 * Wraps an externally-provided plaintext DEK under the active KEK. Used when the caller
 * already holds DEK material (e.g. during a KEK rotation backfill where the DEK identity
 * must be preserved across wrap algorithms).
 *
 * Emits a `DEK_WRAPPED` audit event on success.
 */
class WrapDekUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    suspend fun execute(
        dekBytes: ByteArray,
        actorSubject: String?,
    ): WrappedDek {
        val wrapped = crypto.wrapDek(dekBytes)
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.DEK_WRAPPED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"algorithm":"${wrapped.algorithm}"}""",
            ),
        )
        return wrapped
    }
}
