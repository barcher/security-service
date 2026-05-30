package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.OAuthClientsTable
import com.shared.security.application.ports.OAuthClientRegistry
import com.shared.security.application.ports.OAuthClientStore
import com.shared.security.domain.oauth.OAuthClient
import com.shared.security.domain.oauth.OAuthClientAuthMethod
import com.shared.security.domain.oauth.OAuthGrantType
import com.shared.security.domain.oauth.OAuthScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import org.jetbrains.exposed.exceptions.ExposedSQLException
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction

/**
 * Exposed-backed implementation of the static OAuth client registry (read [OAuthClientRegistry]
 * + provisioning [OAuthClientStore]).
 *
 * The grant-type / scope / audience lists are persisted as space-delimited token strings (the
 * OAuth wire form) and parsed back into domain VOs on read. `auth_method` is persisted as its
 * RFC wire spelling.
 */
class ExposedOAuthClientRepository(
    private val database: Database,
) : OAuthClientRegistry, OAuthClientStore {
    override suspend fun findByClientId(clientId: String): OAuthClient? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                OAuthClientsTable
                    .selectAll()
                    .where { OAuthClientsTable.clientId eq clientId }
                    .limit(1)
                    .firstOrNull()
                    ?.toClient()
            }
        }

    override suspend fun findBySubjectDn(subjectDn: String): OAuthClient? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                OAuthClientsTable
                    .selectAll()
                    .where { OAuthClientsTable.subjectDn eq subjectDn }
                    .limit(1)
                    .firstOrNull()
                    ?.toClient()
            }
        }

    override suspend fun findAll(): List<OAuthClient> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                OAuthClientsTable.selectAll().map { it.toClient() }
            }
        }

    override suspend fun insertIfAbsent(client: OAuthClient): Boolean =
        withContext(Dispatchers.IO) {
            try {
                transaction(database) {
                    val now = Clock.System.now()
                    OAuthClientsTable.insert {
                        it[clientId] = client.clientId
                        it[authMethod] = client.authMethod.wireValue
                        it[subjectDn] = client.subjectDn
                        it[allowedGrantTypes] = client.allowedGrantTypes.joinToString(" ") { g -> g.wireValue }
                        it[allowedScopes] = client.allowedScopes.joinToString(" ") { s -> s.value }
                        it[allowedAudiences] = client.allowedAudiences.joinToString(" ")
                        it[enabled] = client.enabled
                        it[createdAt] = now
                        it[updatedAt] = now
                    }
                }
                true
            } catch (e: ExposedSQLException) {
                // Primary-key (client_id) or subject-DN unique clash: the client already
                // exists. Seeding is idempotent — report "already present" rather than throw.
                if (isDuplicateKey(e)) false else throw e
            }
        }

    private fun isDuplicateKey(e: ExposedSQLException): Boolean {
        val messages = sequenceOf(e.message, e.cause?.message, e.sqlState).filterNotNull()
        return messages.any { "Duplicate entry" in it || "23000" == it || "uk_oauth_clients_subject_dn" in it }
    }

    private fun ResultRow.toClient(): OAuthClient {
        val authMethod =
            OAuthClientAuthMethod.fromWireValue(this[OAuthClientsTable.authMethod])
                ?: error("Unknown auth_method '${this[OAuthClientsTable.authMethod]}' for client")
        return OAuthClient(
            clientId = this[OAuthClientsTable.clientId],
            authMethod = authMethod,
            subjectDn = this[OAuthClientsTable.subjectDn],
            allowedGrantTypes = parseGrantTypes(this[OAuthClientsTable.allowedGrantTypes]),
            allowedScopes = parseScopes(this[OAuthClientsTable.allowedScopes]),
            allowedAudiences = parseTokens(this[OAuthClientsTable.allowedAudiences]).toSet(),
            enabled = this[OAuthClientsTable.enabled],
        )
    }

    private fun parseGrantTypes(raw: String): Set<OAuthGrantType> =
        parseTokens(raw)
            .map { OAuthGrantType.fromWireValue(it) ?: error("Unknown grant_type '$it'") }
            .toSet()

    private fun parseScopes(raw: String): Set<OAuthScope> = parseTokens(raw).map { OAuthScope.of(it) }.toSet()

    private fun parseTokens(raw: String): List<String> = raw.split(" ").filter { it.isNotBlank() }
}
