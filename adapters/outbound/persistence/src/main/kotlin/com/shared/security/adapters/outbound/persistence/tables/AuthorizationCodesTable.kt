package com.shared.security.adapters.outbound.persistence.tables

import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Column
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/**
 * Maps to `V10__authorization_codes.sql`.
 *
 * `code_hash` is a one-way hash (VARBINARY(32)) and the primary key. `code_challenge_method`
 * is the DB ENUM('S256') mapped as a plain varchar (only one legal value today); the
 * repository converts to/from `domain.oauth.PkceChallengeMethod`. `scopes` holds the
 * space-delimited consented scope set.
 */
object AuthorizationCodesTable : Table("authorization_codes") {
    val codeHash = binary("code_hash", length = CODE_HASH_LENGTH)
    val clientId = varchar("client_id", length = CLIENT_ID_LENGTH)
    val subject = varchar("subject", length = SUBJECT_LENGTH)
    val redirectUri = varchar("redirect_uri", length = REDIRECT_URI_LENGTH)
    val codeChallenge = varchar("code_challenge", length = CODE_CHALLENGE_LENGTH)
    val codeChallengeMethod = varchar("code_challenge_method", length = CHALLENGE_METHOD_LENGTH)
    val scopes = varchar("scopes", length = SCOPES_LENGTH)
    val issuedAt = timestamp("issued_at")
    val expiresAt = timestamp("expires_at")
    val redeemedAt: Column<Instant?> = timestamp("redeemed_at").nullable()

    override val primaryKey: PrimaryKey = PrimaryKey(codeHash)

    private const val CODE_HASH_LENGTH = 32
    private const val CLIENT_ID_LENGTH = 255
    private const val SUBJECT_LENGTH = 255
    private const val REDIRECT_URI_LENGTH = 2048
    private const val CODE_CHALLENGE_LENGTH = 128
    private const val CHALLENGE_METHOD_LENGTH = 8
    private const val SCOPES_LENGTH = 1024
}
