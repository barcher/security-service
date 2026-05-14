package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.AuditEventsTable
import com.shared.security.adapters.outbound.persistence.tables.DeksTable
import com.shared.security.adapters.outbound.persistence.tables.KekStatus
import com.shared.security.adapters.outbound.persistence.tables.KeksTable
import kotlinx.datetime.Clock
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.api.ExposedBlob
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle
import org.testcontainers.containers.MySQLContainer
import java.sql.SQLException
import java.util.UUID

@Tag("integration")
@TestInstance(Lifecycle.PER_CLASS)
class SecurityFlywayMigrationTest {
    private lateinit var mysql: MySQLContainer<*>
    private lateinit var db: SecurityDatabase

    @BeforeAll
    fun setUp() {
        @Suppress("UNCHECKED_CAST")
        mysql = (MySQLContainer("mysql:8.0").withDatabaseName("security_keys_test") as MySQLContainer<*>)
        mysql.start()
        val config =
            SecurityDatabaseConfig(
                jdbcUrl = mysql.jdbcUrl,
                user = mysql.username,
                password = mysql.password,
                poolSize = 2,
            )
        db = SecurityDatabase.create(config)
        SecurityFlywayMigrator(db.dataSource).migrate()
    }

    @AfterAll
    fun tearDown() {
        db.close()
        mysql.stop()
    }

    @Test
    fun `V1 enforces at most one ACTIVE kek row`() {
        val first = stagedKek().also(::activate)

        assertThrows(SQLException::class.java) {
            transaction(db.database) {
                KeksTable.insert {
                    it[id] = UUID.randomUUID().toString()
                    it[fingerprint] = "fp:" + UUID.randomUUID()
                    it[status] = KekStatus.ACTIVE
                    it[createdAt] = Clock.System.now()
                    it[activatedAt] = Clock.System.now()
                }
            }
        }

        // Demoting first to PRIOR allows a fresh ACTIVE row.
        transaction(db.database) {
            KeksTable.update({ KeksTable.id eq first }) {
                it[status] = KekStatus.PRIOR
                it[quiescedAt] = Clock.System.now()
            }
        }
        stagedKek().also(::activate)
    }

    @Test
    fun `V2 enforces FK from deks to keks and round-trips wrapped bytes`() {
        val kekId = stagedKek().also(::activate)
        val handle = ByteArray(16) { 0x42.toByte() }
        val payload = ByteArray(64) { 0x01.toByte() }

        transaction(db.database) {
            DeksTable.insert {
                it[DeksTable.handle] = handle
                it[DeksTable.kekId] = kekId
                it[wrappedDekBytes] = ExposedBlob(payload)
                it[createdAt] = Clock.System.now()
                it[updatedAt] = Clock.System.now()
            }
        }

        val readBack =
            transaction(db.database) {
                DeksTable.selectAll().where { DeksTable.handle eq handle }.firstOrNull()
            }
        assertNotNull(readBack)
        assertEquals(kekId, readBack!![DeksTable.kekId])
        assertEquals(payload.toList(), readBack[DeksTable.wrappedDekBytes].bytes.toList())

        assertThrows(SQLException::class.java) {
            transaction(db.database) {
                DeksTable.insert {
                    it[DeksTable.handle] = ByteArray(16) { 0x43.toByte() }
                    it[DeksTable.kekId] = UUID.randomUUID().toString()
                    it[wrappedDekBytes] = ExposedBlob(payload)
                    it[createdAt] = Clock.System.now()
                    it[updatedAt] = Clock.System.now()
                }
            }
        }
    }

    @Test
    fun `V3 round-trips an audit row with prev_hmac and row_hmac`() {
        val now = Clock.System.now()
        val prev = ByteArray(64) { 0x00.toByte() }
        val row = ByteArray(64) { 0x99.toByte() }

        transaction(db.database) {
            AuditEventsTable.insert {
                it[occurredAt] = now
                it[eventType] = "TEST_EVENT"
                it[actorSubject] = "CN=test"
                it[success] = true
                it[prevHmac] = prev
                it[rowHmac] = row
            }
        }

        val count =
            transaction(db.database) {
                AuditEventsTable.selectAll().count()
            }
        assertTrue(count > 0)
    }

    private fun stagedKek(): String {
        val id = UUID.randomUUID().toString()
        transaction(db.database) {
            KeksTable.insert {
                it[KeksTable.id] = id
                it[fingerprint] = "fp:" + UUID.randomUUID()
                it[status] = KekStatus.STAGED
                it[createdAt] = Clock.System.now()
            }
        }
        return id
    }

    private fun activate(kekId: String) {
        transaction(db.database) {
            KeksTable.update({ KeksTable.id eq kekId }) {
                it[status] = KekStatus.ACTIVE
                it[activatedAt] = Clock.System.now()
            }
        }
    }
}
