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
 * SKS-K17 — Daily sweep that walks the QUIESCED → RETIRED → DELETED tail of the JWT
 * signing-key lifecycle:
 *
 *   1. QUIESCED keys whose `quiesced_at + retentionWindow < now` are RETIRED. The repo
 *      sets `retain_until = now + retentionDays`. RETIRED keys are not published and
 *      cannot mint tokens.
 *   2. RETIRED keys whose `retain_until < now` are deleted from the table. The audit log
 *      retains the lifecycle history independently — the row deletion is purely a DB
 *      footprint concern.
 */
class RunJwtSigningKeyRetentionUseCase(
    private val repo: JwtSigningKeyRepository,
    private val auditLog: AuditLogPort,
    private val retentionWindow: Duration,
    private val retentionDays: Long,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(): Summary {
        val now = clock.now()
        val retireCutoff = Instant.fromEpochSeconds(now.epochSeconds - retentionWindow.inWholeSeconds)

        val eligibleQuiesced =
            repo.findAllPriorAndQuiesced().filter { rec ->
                val quiescedAt = rec.quiescedAt
                rec.status == JwtSigningKeyStatus.QUIESCED && quiescedAt != null && quiescedAt < retireCutoff
            }
        var retired = 0
        for (rec in eligibleQuiesced) {
            if (repo.retireQuiesced(rec.kid, now, retentionDays = retentionDays)) {
                retired++
                auditLog.write(
                    AuditEvent(
                        occurredAt = now,
                        eventType = AuditEventType.JWKS_KEY_RETIRED,
                        actorSubject = null,
                        success = true,
                        detailJson = """{"kid":"${rec.kid.toHex()}","retentionDays":$retentionDays}""",
                    ),
                )
            }
        }

        var deleted = 0
        for (rec in repo.findRetiredEligibleForDelete(now)) {
            if (repo.deleteRetired(rec.kid)) {
                deleted++
                auditLog.write(
                    AuditEvent(
                        occurredAt = now,
                        eventType = AuditEventType.JWKS_KEY_DELETED,
                        actorSubject = null,
                        success = true,
                        detailJson = """{"kid":"${rec.kid.toHex()}"}""",
                    ),
                )
            }
        }
        return Summary(retired = retired, deleted = deleted)
    }

    data class Summary(val retired: Int, val deleted: Int)
}
