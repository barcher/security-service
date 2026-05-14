package com.shared.security.adapters.outbound.persistence.tables

import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/** Maps to `V2__deks.sql`. Stores wrapped DEK blobs keyed by opaque handle. */
object DeksTable : Table("deks") {
    val handle = binary("handle", length = 16)
    val kekId = char("kek_id", length = 36) references KeksTable.id
    val wrappedDekBytes = blob("wrapped_dek_bytes")
    val wrappedDekBytesPending = blob("wrapped_dek_bytes_pending").nullable()
    val createdAt = timestamp("created_at")
    val updatedAt = timestamp("updated_at")

    // Stream-E (V4) provenance — set by `import-monolith-deks` CLI; null for DEKs minted
    // natively by the security service. UNIQUE index on this column makes the CLI
    // structurally idempotent.
    val legacyKeyId = varchar("legacy_key_id", length = 36).nullable().uniqueIndex("uk_deks_legacy_key_id")

    override val primaryKey: PrimaryKey = PrimaryKey(handle)
}
