package com.shared.security.adapters.outbound.persistence.audit

import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/**
 * Stream C follow-up SHIP-02 — single-row checkpoint table backing the audit-log shipper
 * and the audit-retention job. See `V6__audit_shipped_checkpoint.sql`.
 */
object AuditShippedCheckpointTable : Table("audit_shipped_checkpoint") {
    val id = byte("id")
    val lastShippedId = long("last_shipped_id")
    val updatedAt = timestamp("updated_at")
    override val primaryKey: PrimaryKey = PrimaryKey(id)
}
