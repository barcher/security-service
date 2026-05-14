package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import kotlinx.datetime.Clock

/**
 * Drives `KekRotationHealthJob` (hourly): generates and unwraps a probe DEK to verify the
 * active KEK is functional end-to-end. Emits `HEALTH_CHECK_OK` on success and
 * `HEALTH_CHECK_FAILED` on any exception. The job classification carries through to the
 * audit chain so an attacker who silently corrupts the active KEK is caught at the next
 * tick rather than at the next live unwrap.
 */
class RunKekHealthCheckUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    suspend fun execute(actorSubject: String? = "security-service:KekRotationHealthJob"): Result {
        val now = Clock.System.now()
        return try {
            val generated = crypto.generateDek()
            val recovered = crypto.unwrapDek(generated.wrapped)
            generated.plaintextBytes.fill(0)
            recovered.fill(0)
            auditLog.write(
                AuditEvent(
                    occurredAt = now,
                    eventType = AuditEventType.HEALTH_CHECK_OK,
                    actorSubject = actorSubject,
                    success = true,
                ),
            )
            Result.OK
        } catch (e: Exception) {
            auditLog.write(
                AuditEvent(
                    occurredAt = now,
                    eventType = AuditEventType.HEALTH_CHECK_FAILED,
                    actorSubject = actorSubject,
                    success = false,
                    detailJson = """{"exception":"${e.javaClass.simpleName}"}""",
                ),
            )
            Result.Failed(e)
        }
    }

    sealed interface Result {
        data object OK : Result

        data class Failed(val cause: Throwable) : Result
    }
}
