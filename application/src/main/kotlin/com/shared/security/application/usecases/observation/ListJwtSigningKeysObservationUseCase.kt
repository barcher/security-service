package com.shared.security.application.usecases.observation

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRepository
import kotlinx.datetime.Clock

/**
 * Stream L L.0 (SKS-L05) — read-only JWT signing-key lifecycle view for the dashboard.
 *
 * Surfaces every row in `jwt_signing_keys` (STAGED, ACTIVE, PRIOR, QUIESCED, RETIRED) so
 * the operator can see the rotation history. Strips both `wrappedPrivateKeyBytes` AND
 * `publicKeySpki`:
 *
 *   * Private bytes are KEK-wrapped + AAD-bound but still credential-class material —
 *     never displayed.
 *   * Public SPKI is intentionally public (it's served via `/v1/jwks`) but doesn't
 *     belong on the dashboard's lifecycle view; the dashboard's job is "what's the
 *     status", not "what's the key bytes". Keep them off-screen.
 *
 * **Audit:** one [AuditEventType.DASHBOARD_OBSERVED] per call.
 */
class ListJwtSigningKeysObservationUseCase(
    private val repo: JwtSigningKeyRepository,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(actorSubject: String?): List<JwtSigningKeyObservation> {
        val records = repo.findAll()
        auditLog.write(
            AuditEvent(
                occurredAt = clock.now(),
                eventType = AuditEventType.DASHBOARD_OBSERVED,
                actorSubject = actorSubject,
                success = true,
                detailJson = """{"resource":"jwt-signing-keys","rowCount":${records.size}}""",
            ),
        )
        return records.map { rec ->
            JwtSigningKeyObservation(
                kidHex = rec.kid.joinToString("") { "%02x".format(it) },
                status = rec.status.name,
                algorithm = rec.algorithm,
                curve = rec.curve,
                wrappedUnderKekId = rec.wrappedUnderKekId,
                createdAt = rec.createdAt,
                activatedAt = rec.activatedAt,
                quiescedAt = rec.quiescedAt,
                retiredAt = rec.retiredAt,
                retainUntil = rec.retainUntil,
            )
        }
    }
}
