package com.shared.security.adapters.outbound.persistence.tables

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.json.json
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/** Maps to `V3__audit_events.sql`. The HMAC-SHA-512 chain columns are at the end. */
object AuditEventsTable : Table("audit_events") {
    val id = long("id").autoIncrement()
    val occurredAt = timestamp("occurred_at")
    val eventType = varchar("event_type", length = 40)
    val actorSubject = varchar("actor_subject", length = 255).nullable()
    val dekHandle = binary("dek_handle", length = 16).nullable()
    val kekId = char("kek_id", length = 36).nullable()
    val success = bool("success")
    val detailJson = json<JsonElement>("detail_json", Json).nullable()

    /** HMAC-SHA-512 of the immediately prior row (zero-byte sentinel for id=1). */
    val prevHmac = binary("prev_hmac", length = 64)

    /** HMAC-SHA-512(AUDIT_HMAC_KEY, canonical_payload || prev_hmac). */
    val rowHmac = binary("row_hmac", length = 64)

    override val primaryKey: PrimaryKey = PrimaryKey(id)
}
