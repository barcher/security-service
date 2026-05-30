package com.shared.security.adapters.outbound.persistence.tables

import org.jetbrains.exposed.sql.Column
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp

/**
 * Maps to `V9__oauth_clients.sql`.
 *
 * `auth_method` is the DB ENUM('tls_client_auth','none'); it is mapped here as a plain
 * varchar holding the RFC wire spelling (`tls_client_auth` / `none`) rather than an Exposed
 * `enumerationByName`, because those wire spellings are not valid Kotlin enum-constant names.
 * The repository converts to/from `domain.oauth.OAuthClientAuthMethod` via its `wireValue`.
 * The grant-type / scope / audience lists are stored as space-delimited token strings (the
 * OAuth wire form), parsed into VOs by the repository.
 */
object OAuthClientsTable : Table("oauth_clients") {
    val clientId = varchar("client_id", length = CLIENT_ID_LENGTH)
    val authMethod = varchar("auth_method", length = AUTH_METHOD_LENGTH)
    val subjectDn: Column<String?> = varchar("subject_dn", length = SUBJECT_DN_LENGTH).nullable()
    val allowedGrantTypes = varchar("allowed_grant_types", length = GRANT_TYPES_LENGTH)
    val allowedScopes = varchar("allowed_scopes", length = SCOPES_LENGTH)
    val allowedAudiences = varchar("allowed_audiences", length = AUDIENCES_LENGTH)
    val enabled = bool("enabled")
    val createdAt = timestamp("created_at")
    val updatedAt = timestamp("updated_at")

    override val primaryKey: PrimaryKey = PrimaryKey(clientId)

    private const val CLIENT_ID_LENGTH = 255
    private const val AUTH_METHOD_LENGTH = 16
    private const val SUBJECT_DN_LENGTH = 512
    private const val GRANT_TYPES_LENGTH = 512
    private const val SCOPES_LENGTH = 1024
    private const val AUDIENCES_LENGTH = 1024
}
