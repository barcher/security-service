package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRepository
import kotlinx.datetime.Clock

/**
 * SKS-K06 — Promote a STAGED JWT signing key to ACTIVE. Atomic with respect to the
 * existing ACTIVE row (if any): the repository demotes ACTIVE → PRIOR in the same
 * transaction that promotes STAGED → ACTIVE. The MySQL singleton-ACTIVE generated-column
 * unique index makes any concurrent dual-promote attempt structurally impossible.
 */
class ActivateJwtSigningKeyUseCase(
    private val repo: JwtSigningKeyRepository,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(
        kid: ByteArray,
        actorSubject: String?,
    ): Result {
        val now = clock.now()
        val activated = repo.activate(kid, now)
        if (!activated) {
            return Result.NotStaged
        }
        auditLog.write(
            AuditEvent(
                occurredAt = now,
                eventType = AuditEventType.JWKS_KEY_ACTIVATED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"kid":"${kid.toHex()}"}""",
            ),
        )
        return Result.Activated
    }

    sealed interface Result {
        data object Activated : Result

        /** The supplied [kid] did not refer to a STAGED row (already promoted or missing). */
        data object NotStaged : Result
    }
}
