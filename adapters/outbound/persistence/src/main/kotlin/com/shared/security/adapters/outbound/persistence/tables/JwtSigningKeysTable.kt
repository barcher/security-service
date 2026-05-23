package com.shared.security.adapters.outbound.persistence.tables

import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Column
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/** Maps to `V5__jwt_signing_keys.sql`. */
object JwtSigningKeysTable : Table("jwt_signing_keys") {
    val kid = binary("kid", length = KID_LENGTH)
    val status = enumerationByName<JwtSigningKeyStatusValue>("status", length = STATUS_COLUMN_LENGTH)
    val algorithm = varchar("algorithm", length = ALGORITHM_COLUMN_LENGTH)
    val curve = varchar("curve", length = CURVE_COLUMN_LENGTH)
    val wrappedPrivateKeyBytes = blob("wrapped_private_key_bytes")
    val publicKeySpki = blob("public_key_spki")
    val wrappedUnderKekId = char("wrapped_under_kek_id", length = KEK_ID_LENGTH)
    val createdAt = timestamp("created_at")
    val activatedAt: Column<Instant?> = timestamp("activated_at").nullable()
    val quiescedAt: Column<Instant?> = timestamp("quiesced_at").nullable()
    val retiredAt: Column<Instant?> = timestamp("retired_at").nullable()
    val retainUntil: Column<Instant?> = timestamp("retain_until").nullable()

    override val primaryKey: PrimaryKey = PrimaryKey(kid)

    private const val KID_LENGTH = 16
    private const val STATUS_COLUMN_LENGTH = 16
    private const val ALGORITHM_COLUMN_LENGTH = 8
    private const val CURVE_COLUMN_LENGTH = 16
    private const val KEK_ID_LENGTH = 36
}

/** Wire-side enum names match `application.ports.JwtSigningKeyStatus`. */
enum class JwtSigningKeyStatusValue {
    STAGED,
    ACTIVE,
    PRIOR,
    QUIESCED,
    RETIRED,
}
