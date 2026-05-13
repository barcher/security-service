package com.workautomations.security.application.usecases

import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditEventType
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.application.ports.CryptoKeyServicePort
import com.workautomations.security.application.ports.KekPair
import kotlinx.datetime.Clock

/**
 * Generates a fresh ML-KEM-768 keypair intended to become the next KEK.
 *
 * Stream B exposes this via `POST /v1/admin/rotate-kek` as the trigger for an operator-led
 * rotation. Stream C wires the resulting keypair into the `keks` table and drives the
 * STAGED → ACTIVE state machine; this use case only produces the material and audits the
 * request — it does NOT activate the new KEK or migrate live DEKs.
 */
class GenerateNewKekPairUseCase(
    private val crypto: CryptoKeyServicePort,
    private val auditLog: AuditLogPort,
) {
    fun execute(actorSubject: String?): KekPair {
        val pair = crypto.generateNewKekPair()
        return pair.also { audit(actorSubject) }
    }

    private fun audit(actorSubject: String?) {
        kotlinx.coroutines.runBlocking {
            auditLog.write(
                AuditEvent(
                    occurredAt = Clock.System.now(),
                    eventType = AuditEventType.KEK_ROTATION_REQUESTED,
                    actorSubject = actorSubject,
                    success = true,
                    detailJson = """{"phase":"key_material_generated"}""",
                ),
            )
        }
    }
}
