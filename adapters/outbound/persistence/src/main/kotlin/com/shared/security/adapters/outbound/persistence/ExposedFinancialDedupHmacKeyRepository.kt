package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.FinancialDedupHmacKeyStatusValue
import com.shared.security.adapters.outbound.persistence.tables.FinancialDedupHmacKeyTable
import com.shared.security.application.ports.FinancialDedupHmacKeyRecord
import com.shared.security.application.ports.FinancialDedupHmacKeyRepository
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

class ExposedFinancialDedupHmacKeyRepository(
    private val database: Database,
) : FinancialDedupHmacKeyRepository {
    override suspend fun findActive(): FinancialDedupHmacKeyRecord? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                FinancialDedupHmacKeyTable
                    .selectAll()
                    .where { FinancialDedupHmacKeyTable.status eq FinancialDedupHmacKeyStatusValue.ACTIVE }
                    .limit(1)
                    .firstOrNull()
                    ?.toRecord()
            }
        }

    override suspend fun insertActive(record: FinancialDedupHmacKeyRecord): Boolean =
        withContext(Dispatchers.IO) {
            try {
                transaction(database) {
                    FinancialDedupHmacKeyTable.insert {
                        it[id] = record.id
                        it[version] = record.version
                        it[status] = FinancialDedupHmacKeyStatusValue.ACTIVE
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
        return messages.any { "uk_financial_dedup_hmac_key_active_singleton" in it || "23000" == it }
    }

    private fun ResultRow.toRecord(): FinancialDedupHmacKeyRecord =
        FinancialDedupHmacKeyRecord(
            id = this[FinancialDedupHmacKeyTable.id],
            version = this[FinancialDedupHmacKeyTable.version],
            wrappedKeyBytes = this[FinancialDedupHmacKeyTable.wrappedKeyBytes].bytes,
            wrappedUnderKekId = this[FinancialDedupHmacKeyTable.wrappedUnderKekId],
            createdAt = this[FinancialDedupHmacKeyTable.createdAt],
        )
}
