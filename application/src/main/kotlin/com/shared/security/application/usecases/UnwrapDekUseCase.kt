package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.WrappedDek
import kotlinx.datetime.Clock

/**
 * Unwraps a previously-wrapped DEK under the active KEK private key.
 *
 * Emits `DEK_UNWRAPPED` (success) or `DEK_UNWRAPPED` with `success=false` on failure. The
 * failure event is critical for audit — a flood of failed unwraps from a single actor is
 * one of the strongest signals of an oracle-abuse attempt and is rate-limited by SKS-B05.
 */
class UnwrapDekUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    suspend fun execute(
        wrapped: WrappedDek,
        actorSubject: String?,
    ): ByteArray {
        val now = Clock.System.now()
        return try {
            val plaintext = crypto.unwrapDek(wrapped)
            auditLog.write(
                AuditEvent(
                    occurredAt = now,
                    eventType = AuditEventType.DEK_UNWRAPPED,
                    actorSubject = actorSubject,
                    success = true,
                ),
            )
            plaintext
        } catch (e: javax.crypto.AEADBadTagException) {
            auditLog.write(
                AuditEvent(
                    occurredAt = now,
                    eventType = AuditEventType.DEK_UNWRAPPED,
                    actorSubject = actorSubject,
                    success = false,
                    detailJson = """{"reason":"aead_tag_mismatch"}""",
                ),
            )
            throw e
        } catch (e: IllegalArgumentException) {
            // Bad base64, wrong size, etc. — record without leaking attacker-controlled detail.
            auditLog.write(
                AuditEvent(
                    occurredAt = now,
                    eventType = AuditEventType.DEK_UNWRAPPED,
                    actorSubject = actorSubject,
                    success = false,
                    detailJson = """{"reason":"malformed_input"}""",
                ),
            )
            throw e
        }
    }
}
