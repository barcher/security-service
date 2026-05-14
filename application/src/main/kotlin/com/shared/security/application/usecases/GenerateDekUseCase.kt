package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.WrappedDek
import kotlinx.datetime.Clock

/**
 * Generates a fresh DEK, wraps it under the active KEK, and returns both the wrapped form
 * and the plaintext bytes to the caller.
 *
 * Every successful call writes a `DEK_GENERATED` audit event. Failures propagate without
 * a partial audit row — the caller is expected to handle and log the error.
 *
 * **Caller contract:** plaintext DEK bytes MUST be zeroised after use. The port returns
 * them in [CryptoKeyServicePort.GeneratedDek.plaintextBytes]; the calling route serialises
 * them as base64 to the wire and immediately fills with zeros.
 */
class GenerateDekUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    suspend fun execute(actorSubject: String?): Result {
        val generated = crypto.generateDek()
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.DEK_GENERATED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"algorithm":"${generated.wrapped.algorithm}"}""",
            ),
        )
        return Result(wrapped = generated.wrapped, plaintextBytes = generated.plaintextBytes)
    }

    data class Result(val wrapped: WrappedDek, val plaintextBytes: ByteArray) {
        override fun equals(other: Any?): Boolean = this === other

        override fun hashCode(): Int = System.identityHashCode(this)
    }
}
