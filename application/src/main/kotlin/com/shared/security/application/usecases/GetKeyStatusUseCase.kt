package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import kotlinx.datetime.Clock

/**
 * Returns a redacted, operator-facing snapshot of the active KEK's identity.
 *
 * Stream B exposes a minimal shape: the SHA-256 fingerprint of the active KEK + an
 * `isAvailable` flag. Stream C extends this with the lifecycle states of every KEK row in
 * the `keks` table (STAGED / ACTIVE / PRIOR / RETIRED) and counts of DEKs still bound to
 * each. The shape returned here is forward-compatible — additional fields will be additive.
 */
class GetKeyStatusUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    suspend fun execute(actorSubject: String?): KeyStatusSummary {
        val summary =
            KeyStatusSummary(
                isAvailable = crypto.isAvailable,
                activeKekFingerprint = if (crypto.isAvailable) crypto.getPublicKeyFingerprint() else null,
            )
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.KEY_STATUS_VIEWED,
                actorSubject = actorSubject,
                success = true,
            ),
        )
        return summary
    }

    data class KeyStatusSummary(
        val isAvailable: Boolean,
        val activeKekFingerprint: String?,
    )
}
