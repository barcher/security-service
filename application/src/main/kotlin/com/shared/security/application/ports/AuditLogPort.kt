package com.shared.security.application.ports

import kotlinx.datetime.Instant

/**
 * Writes a single immutable audit event row to the security service's audit chain.
 *
 * Stream B (this stream) emits `MTLS_REJECTED`, `RATE_LIMIT_EXCEEDED`, and crypto-operation
 * events through this port; the only available implementation in Stream B is the SLF4J
 * fallback in `infrastructure/audit/Slf4jAuditLogAdapter.kt`. The HMAC-SHA-512-chained
 * persistent adapter (`ExposedAuditLogRepository`) lands in Stream C (SKS-C05) and replaces
 * the SLF4J binding without changing this contract.
 *
 * Implementations MUST NOT block the calling request for longer than a few milliseconds.
 * If durable storage is slow, queue and persist asynchronously — never drop events silently.
 */
interface AuditLogPort {
    suspend fun write(event: AuditEvent)
}

/**
 * Single audit event row. Maps 1:1 to proposal §10 `security_keys.audit_events` columns.
 *
 * - [eventType] is one of the values listed in §10 (e.g. `MTLS_REJECTED`, `DEK_GENERATED`,
 *   `DEK_UNWRAPPED`, `RATE_LIMIT_EXCEEDED`, `KEK_ROTATED`, ...).
 * - [actorSubject] is the mTLS client cert subject DN; null when the request was rejected
 *   before client identity could be established (e.g. handshake failure).
 * - [detailJson] is free-form structured detail; must NOT include any secret material (no
 *   DEK plaintext, no KEK material, no full ciphertext payloads — short identifiers only).
 */
data class AuditEvent(
    val occurredAt: Instant,
    val eventType: String,
    val actorSubject: String?,
    val dekHandle: ByteArray? = null,
    val kekId: String? = null,
    val success: Boolean,
    val detailJson: String? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AuditEvent) return false
        return occurredAt == other.occurredAt &&
            eventType == other.eventType &&
            actorSubject == other.actorSubject &&
            dekHandle.contentEqualsNullable(other.dekHandle) &&
            kekId == other.kekId &&
            success == other.success &&
            detailJson == other.detailJson
    }

    override fun hashCode(): Int {
        var result = occurredAt.hashCode()
        result = HASH_FACTOR * result + eventType.hashCode()
        result = HASH_FACTOR * result + (actorSubject?.hashCode() ?: 0)
        result = HASH_FACTOR * result + (dekHandle?.contentHashCode() ?: 0)
        result = HASH_FACTOR * result + (kekId?.hashCode() ?: 0)
        result = HASH_FACTOR * result + success.hashCode()
        result = HASH_FACTOR * result + (detailJson?.hashCode() ?: 0)
        return result
    }

    private companion object {
        private const val HASH_FACTOR = 31
    }
}

private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
    when {
        this == null && other == null -> true
        this == null || other == null -> false
        else -> contentEquals(other)
    }

/** Canonical event-type strings used by routes/use cases across all streams. */
@Suppress("TooManyFunctions") // domain enum-like catalog; non-negotiable
object AuditEventType {
    // Auth / route layer (Stream B)
    const val MTLS_REJECTED = "MTLS_REJECTED"
    const val RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    const val ADMIN_FORBIDDEN = "ADMIN_FORBIDDEN"

    // DEK operations (Stream B)
    const val DEK_GENERATED = "DEK_GENERATED"
    const val DEK_WRAPPED = "DEK_WRAPPED"
    const val DEK_UNWRAPPED = "DEK_UNWRAPPED"
    const val DEK_REWRAPPED = "DEK_REWRAPPED"

    // Admin operations (Stream B + C)
    const val KEK_ROTATION_REQUESTED = "KEK_ROTATION_REQUESTED"
    const val KEY_STATUS_VIEWED = "KEY_STATUS_VIEWED"

    // KEK lifecycle (Stream C — emitted by KekRotationHealthJob + KekPriorTtlJob)
    const val KEK_STAGED = "KEK_STAGED"
    const val KEK_ACTIVATED = "KEK_ACTIVATED"
    const val KEK_QUIESCED = "KEK_QUIESCED"
    const val KEK_RETIRED = "KEK_RETIRED"

    // DEK rotation batch (Stream C — emitted by DekRotationJob)
    const val DEK_ROTATION_BATCH_OK = "DEK_ROTATION_BATCH_OK"
    const val DEK_ROTATION_BATCH_FAILED = "DEK_ROTATION_BATCH_FAILED"

    // Health (Stream C — emitted by KekRotationHealthJob)
    const val HEALTH_CHECK_OK = "HEALTH_CHECK_OK"
    const val HEALTH_CHECK_FAILED = "HEALTH_CHECK_FAILED"

    // Audit-chain self-events (Stream C — emitted by AuditLogShipperJob + verification reads)
    const val AUDIT_CHAIN_VERIFIED = "AUDIT_CHAIN_VERIFIED"
    const val AUDIT_CHAIN_BREAK = "AUDIT_CHAIN_BREAK"
    const val AUDIT_SHIPPED = "AUDIT_SHIPPED"
    const val AUDIT_RETENTION_DELETED = "AUDIT_RETENTION_DELETED"

    // KEK backup verification (Stream C — emitted by KekBackupVerifyJob)
    const val KEK_BACKUP_VERIFIED = "KEK_BACKUP_VERIFIED"
    const val KEK_BACKUP_VERIFY_FAILED = "KEK_BACKUP_VERIFY_FAILED"

    // JWT signing-key lifecycle (Stream K — proposal §9)
    const val JWKS_KEY_GENERATED = "JWKS_KEY_GENERATED"
    const val JWKS_KEY_ACTIVATED = "JWKS_KEY_ACTIVATED"
    const val JWKS_KEY_QUIESCED = "JWKS_KEY_QUIESCED"
    const val JWKS_KEY_RETIRED = "JWKS_KEY_RETIRED"
    const val JWKS_KEY_DELETED = "JWKS_KEY_DELETED"
    const val JWKS_HEALTH_CHECK_FAILED = "JWKS_HEALTH_CHECK_FAILED"

    // JWT signing operations (Stream K)
    const val JWT_SIGNED = "JWT_SIGNED"
    const val JWT_AUDIENCE_FORBIDDEN = "JWT_AUDIENCE_FORBIDDEN"
    const val JWT_SIGN_FAILED = "JWT_SIGN_FAILED"

    // Observability surface (Stream L L.0) — emitted by ObservabilityRoutes for every
    // GET under /v1/observability/. The dashboard-observer mTLS lane is structurally
    // separate from the admin lane so these rows have a distinct actor_subject prefix
    // for forensics.
    const val DASHBOARD_OBSERVED = "DASHBOARD_OBSERVED"
    const val OBSERVER_FORBIDDEN = "OBSERVER_FORBIDDEN"
    const val OBSERVABILITY_RATE_LIMIT_EXCEEDED = "OBSERVABILITY_RATE_LIMIT_EXCEEDED"
    const val OBSERVABILITY_ERROR = "OBSERVABILITY_ERROR"
}
