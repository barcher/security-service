package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration

/**
 * SKS-K16 — Daily sweep that quiesces PRIOR JWT signing keys whose `quiescedAt` would be
 * past the configured TTL. Once a key is quiesced it is dropped from /v1/jwks and is no
 * longer used for verification by consumers (the JWKS cache will evict it on next refresh).
 *
 * Default TTL: 24 h after `activated_at`. Mirrors KEK PRIOR-TTL but with a JWT-specific
 * shorter window because JWT access tokens are short-lived (≤24 h per the route cap), so a
 * 24 h quiesce window is enough for any in-flight token to expire naturally.
 */
class RunJwtSigningKeyPriorTtlUseCase(
    private val repo: JwtSigningKeyRepository,
    private val auditLog: AuditLogPort,
    private val ttl: Duration,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(): Summary {
        val now = clock.now()
        val cutoff = Instant.fromEpochSeconds(now.epochSeconds - ttl.inWholeSeconds)
        val candidates = repo.findAllPriorAndQuiesced().filter { it.status == JwtSigningKeyStatus.PRIOR }

        var quiesced = 0
        var blockedByTtl = 0
        for (rec in candidates) {
            val activatedAt = rec.activatedAt
            if (activatedAt == null || activatedAt >= cutoff) {
                blockedByTtl++
                continue
            }
            if (repo.quiescePrior(rec.kid, now)) {
                quiesced++
                auditLog.write(
                    AuditEvent(
                        occurredAt = now,
                        eventType = AuditEventType.JWKS_KEY_QUIESCED,
                        actorSubject = null,
                        success = true,
                        detailJson = """{"kid":"${rec.kid.toHex()}","ttlSeconds":${ttl.inWholeSeconds}}""",
                    ),
                )
            }
        }
        return Summary(candidatesEvaluated = candidates.size, quiesced = quiesced, blockedByTtl = blockedByTtl)
    }

    data class Summary(val candidatesEvaluated: Int, val quiesced: Int, val blockedByTtl: Int)
}
