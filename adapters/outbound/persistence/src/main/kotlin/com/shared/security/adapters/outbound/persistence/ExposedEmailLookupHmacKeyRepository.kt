package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.EmailLookupHmacKeyStatusValue
import com.shared.security.adapters.outbound.persistence.tables.EmailLookupHmacKeyTable
import com.shared.security.application.ports.EmailLookupHmacKeyRecord
import com.shared.security.application.ports.EmailLookupHmacKeyRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.exceptions.ExposedSQLException
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.api.ExposedBlob
import org.jetbrains.exposed.sql.transactions.transaction

class ExposedEmailLookupHmacKeyRepository(
    private val database: Database,
) : EmailLookupHmacKeyRepository {
    override suspend fun findActive(): EmailLookupHmacKeyRecord? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                EmailLookupHmacKeyTable
                    .selectAll()
                    .where { EmailLookupHmacKeyTable.status eq EmailLookupHmacKeyStatusValue.ACTIVE }
                    .limit(1)
                    .firstOrNull()
                    ?.toRecord()
            }
        }

    override suspend fun insertActive(record: EmailLookupHmacKeyRecord): Boolean =
        withContext(Dispatchers.IO) {
            try {
                transaction(database) {
                    EmailLookupHmacKeyTable.insert {
                        it[id] = record.id
                        it[version] = record.version
                        it[status] = EmailLookupHmacKeyStatusValue.ACTIVE
                        it[wrappedKeyBytes] = ExposedBlob(record.wrappedKeyBytes)
                        it[wrappedUnderKekId] = record.wrappedUnderKekId
                        it[createdAt] = record.createdAt
                    }
                }
                true
            } catch (e: ExposedSQLException) {
                // Singleton-ACTIVE unique-index race: another caller inserted first. The
                // use case re-reads the winner via findActive().
                if (isActiveSingletonConflict(e)) {
                    false
                } else {
                    throw e
                }
            }
        }

    private fun isActiveSingletonConflict(e: ExposedSQLException): Boolean {
        val messages = sequenceOf(e.message, e.cause?.message, e.sqlState).filterNotNull()
        return messages.any { "uk_email_lookup_hmac_key_active_singleton" in it || "23000" == it }
    }

    private fun ResultRow.toRecord(): EmailLookupHmacKeyRecord =
        EmailLookupHmacKeyRecord(
            id = this[EmailLookupHmacKeyTable.id],
            version = this[EmailLookupHmacKeyTable.version],
            wrappedKeyBytes = this[EmailLookupHmacKeyTable.wrappedKeyBytes].bytes,
            wrappedUnderKekId = this[EmailLookupHmacKeyTable.wrappedUnderKekId],
            createdAt = this[EmailLookupHmacKeyTable.createdAt],
        )
}
