package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.KekEnvelopePort
import kotlinx.datetime.Clock

/**
 * SKS-K15 — Hourly probe that verifies the ACTIVE JWT signing key can sign + verify a
 * fixed payload. Mirrors [com.shared.security.application.usecases.RunKekHealthCheckUseCase].
 * Emits a `JWKS_HEALTH_CHECK_FAILED` audit on any error; emits nothing on success (the
 * absence of failures is the signal — same convention as `KekRotationHealthJob`).
 */
class RunJwtSigningKeyHealthCheckUseCase(
    private val repo: JwtSigningKeyRepository,
    private val kekEnvelope: KekEnvelopePort,
    private val signing: JwtSigningKeyPort,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(): Result {
        val activeKey =
            repo.findActive() ?: run {
                auditLog.write(
                    AuditEvent(
                        occurredAt = clock.now(),
                        eventType = AuditEventType.JWKS_HEALTH_CHECK_FAILED,
                        actorSubject = null,
                        success = false,
                        detailJson = """{"reason":"no_active_key"}""",
                    ),
                )
                return Result.NoActiveKey
            }

        return try {
            val wrapped = WrappedBlobCodec.decode(activeKey.wrappedPrivateKeyBytes)
            val aad = aadFor(activeKey.kid)
            val privateKeyPkcs8 = kekEnvelope.unwrap(wrapped, aad)
            val signature: ByteArray
            try {
                signature = signing.sign(privateKeyPkcs8.copyOf(), PROBE_PAYLOAD)
            } finally {
                privateKeyPkcs8.fill(0)
            }
            val ok = signing.verify(activeKey.publicKeySpki, PROBE_PAYLOAD, signature)
            if (ok) {
                Result.Ok
            } else {
                auditLog.write(failureAudit(activeKey.kid, "verify_returned_false"))
                Result.Failed("verify_returned_false")
            }
        } catch (ex: Exception) {
            auditLog.write(failureAudit(activeKey.kid, ex.javaClass.simpleName))
            Result.Failed(ex.javaClass.simpleName)
        }
    }

    private fun failureAudit(
        kid: ByteArray,
        reason: String,
    ): AuditEvent =
        AuditEvent(
            occurredAt = clock.now(),
            eventType = AuditEventType.JWKS_HEALTH_CHECK_FAILED,
            actorSubject = null,
            success = false,
            detailJson = """{"kid":"${kid.toHex()}","reason":"$reason"}""",
        )

    sealed interface Result {
        data object Ok : Result

        data object NoActiveKey : Result

        data class Failed(val reason: String) : Result
    }

    private companion object {
        private val PROBE_PAYLOAD: ByteArray = "jwks-health-probe".toByteArray(Charsets.US_ASCII)
    }
}
