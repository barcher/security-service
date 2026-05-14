package com.shared.security.adapters.outbound.persistence.tables

import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/** Maps to `V1__keks.sql`. */
object KeksTable : Table("keks") {
    val id = char("id", length = 36)
    val fingerprint = varchar("fingerprint", length = 95).uniqueIndex("uk_keks_fingerprint")
    val status = enumerationByName<KekStatus>("status", length = 16)
    val createdAt = timestamp("created_at")
    val activatedAt: org.jetbrains.exposed.sql.Column<Instant?> = timestamp("activated_at").nullable()
    val quiescedAt: org.jetbrains.exposed.sql.Column<Instant?> = timestamp("quiesced_at").nullable()
    val retiredAt: org.jetbrains.exposed.sql.Column<Instant?> = timestamp("retired_at").nullable()

    override val primaryKey: PrimaryKey = PrimaryKey(id)
}

/**
 * KEK lifecycle states. Single-row invariant enforced at the schema level (one ACTIVE row
 * max via a generated unique index in V1); the application layer transitions states.
 */
enum class KekStatus {
    /** Key material has been generated but is not yet wrapping any DEKs. */
    STAGED,

    /** The current wrap KEK. At most one row at a time. */
    ACTIVE,

    /** Was active; tolerated for unwrap during the quiesce window while DEKs are migrated. */
    PRIOR,

    /** No live DEK references this KEK; the row remains as an audit anchor. */
    RETIRED,
}
