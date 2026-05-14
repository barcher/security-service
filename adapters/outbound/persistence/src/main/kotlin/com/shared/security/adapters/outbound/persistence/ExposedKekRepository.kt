package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.KekStatus
import com.shared.security.adapters.outbound.persistence.tables.KeksTable
import com.shared.security.application.ports.KekLifecycleStatus
import com.shared.security.application.ports.KekRecord
import com.shared.security.application.ports.KekRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update

class ExposedKekRepository(
    private val database: Database,
    private val clock: Clock = Clock.System,
) : KekRepository {
    override suspend fun findActive(): KekRecord? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                KeksTable
                    .selectAll()
                    .where { KeksTable.status eq KekStatus.ACTIVE }
                    .limit(1)
                    .firstOrNull()
                    ?.toRecord()
            }
        }

    override suspend fun findAllPrior(): List<KekRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                KeksTable
                    .selectAll()
                    .where { KeksTable.status eq KekStatus.PRIOR }
                    .orderBy(KeksTable.createdAt)
                    .map { it.toRecord() }
            }
        }

    override suspend fun findById(id: String): KekRecord? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                KeksTable.selectAll().where { KeksTable.id eq id }.firstOrNull()?.toRecord()
            }
        }

    override suspend fun retirePrior(id: String): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                val updated =
                    KeksTable.update({ (KeksTable.id eq id) and (KeksTable.status eq KekStatus.PRIOR) }) {
                        it[status] = KekStatus.RETIRED
                        it[retiredAt] = clock.now()
                    }
                updated > 0
            }
        }

    private fun ResultRow.toRecord(): KekRecord =
        KekRecord(
            id = this[KeksTable.id],
            fingerprint = this[KeksTable.fingerprint],
            status =
                when (this[KeksTable.status]) {
                    KekStatus.STAGED -> KekLifecycleStatus.STAGED
                    KekStatus.ACTIVE -> KekLifecycleStatus.ACTIVE
                    KekStatus.PRIOR -> KekLifecycleStatus.PRIOR
                    KekStatus.RETIRED -> KekLifecycleStatus.RETIRED
                },
            createdAt = this[KeksTable.createdAt],
            activatedAt = this[KeksTable.activatedAt],
            quiescedAt = this[KeksTable.quiescedAt],
            retiredAt = this[KeksTable.retiredAt],
        )
}
