package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.JwtSigningKeyStatusValue
import com.shared.security.adapters.outbound.persistence.tables.JwtSigningKeysTable
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SortOrder
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.or
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.api.ExposedBlob
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update

class ExposedJwtSigningKeyRepository(
    private val database: Database,
) : JwtSigningKeyRepository {
    override suspend fun findActive(): JwtSigningKeyRecord? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable
                    .selectAll()
                    .where { JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.ACTIVE }
                    .limit(1)
                    .firstOrNull()
                    ?.toRecord()
            }
        }

    override suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable
                    .selectAll()
                    .where {
                        (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.PRIOR) or
                            (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.QUIESCED)
                    }
                    .orderBy(JwtSigningKeysTable.createdAt to SortOrder.ASC)
                    .map { it.toRecord() }
            }
        }

    override suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable
                    .selectAll()
                    .where { JwtSigningKeysTable.kid eq kid }
                    .firstOrNull()
                    ?.toRecord()
            }
        }

    override suspend fun findAllPublishable(): List<JwtSigningKeyRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable
                    .selectAll()
                    .where {
                        (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.ACTIVE) or
                            (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.PRIOR)
                    }
                    .map { it.toRecord() }
                    // ACTIVE before PRIOR so consumers pick the freshest signing key when
                    // resolving by status alone. Within PRIOR, oldest-first for determinism.
                    .sortedWith(
                        compareBy(
                            { if (it.status == JwtSigningKeyStatus.ACTIVE) 0 else 1 },
                            { it.createdAt },
                        ),
                    )
            }
        }

    override suspend fun insertStaged(record: JwtSigningKeyRecord) {
        require(record.status == JwtSigningKeyStatus.STAGED) {
            "insertStaged requires record.status == STAGED, was ${record.status}"
        }
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable.insert {
                    it[kid] = record.kid
                    it[status] = JwtSigningKeyStatusValue.STAGED
                    it[algorithm] = record.algorithm
                    it[curve] = record.curve
                    it[wrappedPrivateKeyBytes] = ExposedBlob(record.wrappedPrivateKeyBytes)
                    it[publicKeySpki] = ExposedBlob(record.publicKeySpki)
                    it[wrappedUnderKekId] = record.wrappedUnderKekId
                    it[createdAt] = record.createdAt
                    it[activatedAt] = record.activatedAt
                    it[quiescedAt] = record.quiescedAt
                    it[retiredAt] = record.retiredAt
                    it[retainUntil] = record.retainUntil
                }
            }
        }
    }

    override suspend fun activate(
        kid: ByteArray,
        now: Instant,
    ): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                // Demote the existing ACTIVE (if any) → PRIOR first. The singleton-ACTIVE
                // generated-column unique index would otherwise reject the promote step.
                JwtSigningKeysTable.update({ JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.ACTIVE }) {
                    it[status] = JwtSigningKeyStatusValue.PRIOR
                }
                val promoted =
                    JwtSigningKeysTable.update(
                        {
                            (JwtSigningKeysTable.kid eq kid) and
                                (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.STAGED)
                        },
                    ) {
                        it[status] = JwtSigningKeyStatusValue.ACTIVE
                        it[activatedAt] = now
                    }
                promoted > 0
            }
        }

    override suspend fun quiescePrior(
        kid: ByteArray,
        now: Instant,
    ): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                val updated =
                    JwtSigningKeysTable.update(
                        {
                            (JwtSigningKeysTable.kid eq kid) and
                                (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.PRIOR)
                        },
                    ) {
                        it[status] = JwtSigningKeyStatusValue.QUIESCED
                        it[quiescedAt] = now
                    }
                updated > 0
            }
        }

    override suspend fun retireQuiesced(
        kid: ByteArray,
        now: Instant,
        retentionDays: Long,
    ): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                val retainUntil = Instant.fromEpochSeconds(now.epochSeconds + retentionDays * SECONDS_PER_DAY)
                val updated =
                    JwtSigningKeysTable.update(
                        {
                            (JwtSigningKeysTable.kid eq kid) and
                                (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.QUIESCED)
                        },
                    ) {
                        it[status] = JwtSigningKeyStatusValue.RETIRED
                        it[retiredAt] = now
                        it[JwtSigningKeysTable.retainUntil] = retainUntil
                    }
                updated > 0
            }
        }

    override suspend fun deleteRetired(kid: ByteArray): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                val deleted =
                    JwtSigningKeysTable.deleteWhere {
                        (JwtSigningKeysTable.kid eq kid) and
                            (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.RETIRED)
                    }
                deleted > 0
            }
        }

    override suspend fun findAll(): List<JwtSigningKeyRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable
                    .selectAll()
                    .orderBy(JwtSigningKeysTable.createdAt to SortOrder.DESC)
                    .map { it.toRecord() }
            }
        }

    override suspend fun findRetiredEligibleForDelete(now: Instant): List<JwtSigningKeyRecord> =
        withContext(Dispatchers.IO) {
            transaction(database) {
                JwtSigningKeysTable
                    .selectAll()
                    .where {
                        (JwtSigningKeysTable.status eq JwtSigningKeyStatusValue.RETIRED) and
                            (JwtSigningKeysTable.retainUntil lessEq now)
                    }
                    .map { it.toRecord() }
            }
        }

    private fun ResultRow.toRecord(): JwtSigningKeyRecord =
        JwtSigningKeyRecord(
            kid = this[JwtSigningKeysTable.kid],
            status =
                when (this[JwtSigningKeysTable.status]) {
                    JwtSigningKeyStatusValue.STAGED -> JwtSigningKeyStatus.STAGED
                    JwtSigningKeyStatusValue.ACTIVE -> JwtSigningKeyStatus.ACTIVE
                    JwtSigningKeyStatusValue.PRIOR -> JwtSigningKeyStatus.PRIOR
                    JwtSigningKeyStatusValue.QUIESCED -> JwtSigningKeyStatus.QUIESCED
                    JwtSigningKeyStatusValue.RETIRED -> JwtSigningKeyStatus.RETIRED
                },
            algorithm = this[JwtSigningKeysTable.algorithm],
            curve = this[JwtSigningKeysTable.curve],
            wrappedPrivateKeyBytes = this[JwtSigningKeysTable.wrappedPrivateKeyBytes].bytes,
            publicKeySpki = this[JwtSigningKeysTable.publicKeySpki].bytes,
            wrappedUnderKekId = this[JwtSigningKeysTable.wrappedUnderKekId],
            createdAt = this[JwtSigningKeysTable.createdAt],
            activatedAt = this[JwtSigningKeysTable.activatedAt],
            quiescedAt = this[JwtSigningKeysTable.quiescedAt],
            retiredAt = this[JwtSigningKeysTable.retiredAt],
            retainUntil = this[JwtSigningKeysTable.retainUntil],
        )

    private companion object {
        private const val SECONDS_PER_DAY: Long = 86_400L
    }
}
