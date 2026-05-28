package com.shared.security.adapters.outbound.persistence.tables

import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Column
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/** Maps to `V7__email_lookup_hmac_key.sql`. */
object EmailLookupHmacKeyTable : Table("email_lookup_hmac_key") {
    val id = char("id", length = ID_LENGTH)
    val version = integer("version")
    val status = enumerationByName<EmailLookupHmacKeyStatusValue>("status", length = STATUS_COLUMN_LENGTH)
    val wrappedKeyBytes = blob("wrapped_key_bytes")
    val wrappedUnderKekId = char("wrapped_under_kek_id", length = KEK_ID_LENGTH)
    val createdAt = timestamp("created_at")
    val retiredAt: Column<Instant?> = timestamp("retired_at").nullable()

    override val primaryKey: PrimaryKey = PrimaryKey(id)

    private const val ID_LENGTH = 36
    private const val STATUS_COLUMN_LENGTH = 16
    private const val KEK_ID_LENGTH = 36
}

enum class EmailLookupHmacKeyStatusValue {
    ACTIVE,
    RETIRED,
}
