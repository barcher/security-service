package com.workautomations.security.infrastructure.audit

import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditLogPort
import org.slf4j.LoggerFactory
import java.util.HexFormat

/**
 * Stream-B fallback [AuditLogPort] implementation that writes audit events to SLF4J at INFO.
 *
 * Stream C (SKS-C04, SKS-C05) introduces `ExposedAuditLogRepository`, which is the
 * production adapter — it writes to `security_keys.audit_events` with an HMAC-SHA-512
 * row chain. This SLF4J adapter is replaced by that binding in `SecurityServiceModule`
 * without any change to callers.
 *
 * No secret material is emitted: the [AuditEvent.detailJson] contract forbids it, and this
 * adapter does not extract anything beyond the event's own fields.
 */
class Slf4jAuditLogAdapter : AuditLogPort {
    private val logger = LoggerFactory.getLogger("com.workautomations.security.audit")
    private val hex = HexFormat.of()

    override suspend fun write(event: AuditEvent) {
        val handleHex = event.dekHandle?.let { hex.formatHex(it) } ?: "-"
        logger.info(
            "AUDIT type={} actor={} dekHandle={} kekId={} success={} detail={}",
            event.eventType,
            event.actorSubject ?: "-",
            handleHex,
            event.kekId ?: "-",
            event.success,
            event.detailJson ?: "-",
        )
    }
}
