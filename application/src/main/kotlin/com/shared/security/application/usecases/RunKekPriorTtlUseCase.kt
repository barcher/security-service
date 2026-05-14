package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.KekRecord
import com.shared.security.application.ports.KekRepository
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration

/**
 * Drives `KekPriorTtlJob` (hourly): advances PRIOR KEKs to RETIRED when (a) the quiesce
 * window has elapsed since the KEK was quiesced AND (b) no DEKs still reference it.
 *
 * Per proposal §8.6, condition (b) is the structural requirement: we must not retire a KEK
 * any DEK still depends on. The TTL is a *minimum*; in practice the KEK only retires once
 * `DekRotationJob` has rewrapped every DEK to the active KEK.
 */
class RunKekPriorTtlUseCase(
    private val kekRepository: KekRepository,
    private val dekRepository: DekRepository,
    private val auditLog: AuditLogPort,
    private val quiesceWindow: Duration,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(): Summary {
        val now = clock.now()
        val candidates = kekRepository.findAllPrior()
        var retired = 0
        var blockedByDeks = 0
        var blockedByTtl = 0

        for (kek in candidates) {
            when {
                !ttlElapsed(kek, now) -> blockedByTtl++
                dekRepository.countByKekId(kek.id) > 0 -> blockedByDeks++
                else -> {
                    if (kekRepository.retirePrior(kek.id)) {
                        retired++
                        auditLog.write(
                            AuditEvent(
                                occurredAt = now,
                                eventType = AuditEventType.KEK_RETIRED,
                                actorSubject = "security-service:KekPriorTtlJob",
                                kekId = kek.id,
                                success = true,
                            ),
                        )
                    }
                }
            }
        }
        return Summary(
            candidatesEvaluated = candidates.size,
            retired = retired,
            blockedByDeks = blockedByDeks,
            blockedByTtl = blockedByTtl,
        )
    }

    private fun ttlElapsed(
        kek: KekRecord,
        now: Instant,
    ): Boolean {
        val quiesced = kek.quiescedAt ?: return false
        return (now - quiesced) >= quiesceWindow
    }

    data class Summary(
        val candidatesEvaluated: Int,
        val retired: Int,
        val blockedByDeks: Int,
        val blockedByTtl: Int,
    )
}
