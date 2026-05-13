package com.workautomations.security.application.usecases

import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditEventType
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.application.ports.CryptoKeyServicePort
import com.workautomations.security.application.ports.WrappedDek
import kotlinx.datetime.Clock

/**
 * Re-wraps an existing wrapped DEK under a new KEK public key. Used by the KEK rotation
 * sequence to migrate all live DEKs to a new KEK without changing the underlying DEK bytes.
 *
 * Emits a `DEK_REWRAPPED` audit event.
 */
class RewrapDekUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    suspend fun execute(
        existing: WrappedDek,
        newPublicKeyBytes: ByteArray,
        actorSubject: String?,
    ): WrappedDek {
        val rewrapped = crypto.rewrapDekForNewKek(existing, newPublicKeyBytes)
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.DEK_REWRAPPED,
                actorSubject = actorSubject,
                success = true,
            ),
        )
        return rewrapped
    }
}
