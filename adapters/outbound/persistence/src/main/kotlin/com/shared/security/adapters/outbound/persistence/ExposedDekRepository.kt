package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.DeksTable
import com.shared.security.application.ports.DekRecord
import com.shared.security.application.ports.DekRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SortOrder
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.api.ExposedBlob
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update

class ExposedDekRepository(private val database: Database) : DekRepository {
    override suspend fun countByKekId(kekId: String): Long =
        withContext(Dispatchers.IO) {
            transaction(database) {
                DeksTable.selectAll().where { DeksTable.kekId eq kekId }.count()
            }
        }

    override suspend fun findBatchByKekId(
        kekId: String,
        limit: Int,
    ): List<DekRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                DeksTable
                    .selectAll()
                    .where { DeksTable.kekId eq kekId }
                    .orderBy(DeksTable.createdAt)
                    .limit(limit)
                    .map { it.toRecord() }
            }
        }

    override suspend fun rewrap(
        handle: ByteArray,
        newKekId: String,
        newWrappedBytes: ByteArray,
        updatedAt: Instant,
    ): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                val n =
                    DeksTable.update({ DeksTable.handle eq handle }) {
                        it[kekId] = newKekId
                        it[wrappedDekBytes] = ExposedBlob(newWrappedBytes)
                        it[DeksTable.updatedAt] = updatedAt
                    }
                n > 0
            }
        }

    override suspend fun findRecent(limit: Int): List<DekRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                DeksTable
                    .selectAll()
                    .orderBy(DeksTable.createdAt to SortOrder.DESC)
                    .limit(limit)
                    .map { it.toRecord() }
            }
        }

    override suspend fun countAll(): Long =
        withContext(Dispatchers.IO) {
            transaction(database) { DeksTable.selectAll().count() }
        }

    private fun ResultRow.toRecord(): DekRecord =
        DekRecord(
            handle = this[DeksTable.handle],
            kekId = this[DeksTable.kekId],
            wrappedDekBytes = this[DeksTable.wrappedDekBytes].bytes,
            createdAt = this[DeksTable.createdAt],
            updatedAt = this[DeksTable.updatedAt],
        )
}
