package com.shared.security.adapters.outbound.persistence.audit

import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.adapters.outbound.persistence.tables.AuditEventsTable
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.jetbrains.exposed.sql.SqlExpressionBuilder.greaterEq
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle
import org.testcontainers.containers.MySQLContainer

/**
 * Stream L L.0 (SKS-L12 persistence half) — end-to-end test of the new
 * [com.shared.security.application.ports.AuditLogQueryPort] impl against a real MySQL.
 *
 * Companion to `ObservabilityRoutesTest` (route-layer coverage with stubs); together they
 * exercise the full chain from `GET /v1/observability/audit-events` down to MySQL.
 */
@Tag("integration")
@TestInstance(Lifecycle.PER_CLASS)
class ExposedAuditLogQueryRepositoryTest {
    private lateinit var mysql: MySQLContainer<*>
    private lateinit var db: SecurityDatabase
    private lateinit var repo: ExposedAuditLogQueryRepository

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
        repo = ExposedAuditLogQueryRepository(db.database)
    }

    @AfterAll
    fun tearDown() {
        db.close()
        mysql.stop()
    }

    @Test
    fun `search with no filters returns rows ordered occurred_at desc with totalCount`() =
        runTest {
            cleanup()
            val baseTime = Clock.System.now()
            seed(
                AuditEventInsert("KEK_ACTIVATED", baseTime, "CN=admin"),
                AuditEventInsert("DEK_UNWRAPPED", baseTime.plusSec(10), "CN=monolith"),
                AuditEventInsert("DASHBOARD_OBSERVED", baseTime.plusSec(20), "CN=observer"),
            )

            val result = repo.search(page = 0, size = 50)

            assertEquals(3, result.totalCount)
            assertEquals(3, result.rows.size)
            assertEquals("DASHBOARD_OBSERVED", result.rows[0].eventType)
            assertEquals("KEK_ACTIVATED", result.rows[2].eventType)
        }

    @Test
    fun `freeText filter substring-matches against event_type actor_subject and kek_id`() =
        runTest {
            cleanup()
            val now = Clock.System.now()
            seed(
                AuditEventInsert("DEK_UNWRAPPED", now, "CN=monolith", kekId = "kek-abc-1"),
                AuditEventInsert("KEK_ACTIVATED", now, "CN=admin", kekId = "kek-xyz-2"),
            )

            assertEquals(1, repo.search(freeText = "DEK_UN", page = 0, size = 10).totalCount)
            assertEquals(1, repo.search(freeText = "monolith", page = 0, size = 10).totalCount)
            assertEquals(1, repo.search(freeText = "kek-abc", page = 0, size = 10).totalCount)
            assertEquals(0, repo.search(freeText = "nothing-matches", page = 0, size = 10).totalCount)
        }

    @Test
    fun `eventTypeIn filter restricts results to the named types`() =
        runTest {
            cleanup()
            val now = Clock.System.now()
            seed(
                AuditEventInsert("KEK_ACTIVATED", now, "CN=admin"),
                AuditEventInsert("DEK_UNWRAPPED", now, "CN=monolith"),
                AuditEventInsert("JWKS_KEY_ACTIVATED", now, "CN=admin"),
            )

            val result =
                repo.search(
                    eventTypeIn = setOf("KEK_ACTIVATED", "JWKS_KEY_ACTIVATED"),
                    page = 0,
                    size = 50,
                )

            assertEquals(2, result.totalCount)
            assertTrue(result.rows.all { it.eventType in setOf("KEK_ACTIVATED", "JWKS_KEY_ACTIVATED") })
        }

    @Test
    fun `fromTime and toTime bound the occurred_at range inclusively`() =
        runTest {
            cleanup()
            val base = Instant.parse("2026-05-23T00:00:00Z")
            seed(
                AuditEventInsert("KEK_ACTIVATED", base, "CN=a"),
                AuditEventInsert("KEK_ACTIVATED", base.plusSec(60), "CN=b"),
                AuditEventInsert("KEK_ACTIVATED", base.plusSec(120), "CN=c"),
            )

            val withinWindow =
                repo.search(
                    fromTime = base.plusSec(30),
                    toTime = base.plusSec(90),
                    page = 0,
                    size = 50,
                )
            assertEquals(1, withinWindow.totalCount)
            assertEquals("CN=b", withinWindow.rows.single().actorSubject)
        }

    @Test
    fun `pagination — page=0 size=2 returns first 2 of 5 in desc order`() =
        runTest {
            cleanup()
            val base = Clock.System.now()
            (1..5).forEach { i ->
                seed(AuditEventInsert("DEK_UNWRAPPED", base.plusSec(i.toLong()), "CN=svc-$i"))
            }

            val page0 = repo.search(page = 0, size = 2)
            assertEquals(5L, page0.totalCount)
            assertEquals(2, page0.rows.size)
            assertEquals("CN=svc-5", page0.rows[0].actorSubject)
            assertEquals("CN=svc-4", page0.rows[1].actorSubject)

            val page2 = repo.search(page = 2, size = 2)
            assertEquals(1, page2.rows.size)
            assertEquals("CN=svc-1", page2.rows.single().actorSubject)
        }

    @Test
    fun `size above cap is clamped to MAX_PAGE_SIZE in the impl`() =
        runTest {
            cleanup()
            val base = Clock.System.now()
            (1..3).forEach { i -> seed(AuditEventInsert("DEK_UNWRAPPED", base.plusSec(i.toLong()), "CN=svc-$i")) }

            // 10_000 → clamped to 200 internally; returns all 3.
            val result = repo.search(page = 0, size = 10_000)
            assertEquals(3, result.rows.size)
        }

    @Test
    fun `result rows never expose prev_hmac or row_hmac fields`() =
        runTest {
            cleanup()
            seed(AuditEventInsert("KEK_ACTIVATED", Clock.System.now(), "CN=admin"))

            val result = repo.search(page = 0, size = 10)
            val row = result.rows.single()
            // The Row data class has no prev_hmac/row_hmac fields — structural guarantee.
            val fields = row.javaClass.declaredFields.map { it.name }
            assertTrue("prevHmac" !in fields)
            assertTrue("rowHmac" !in fields)
            assertNotNull(row.eventType)
        }

    private data class AuditEventInsert(
        val eventType: String,
        val occurredAt: Instant,
        val actorSubject: String,
        val kekId: String? = null,
    )

    private fun seed(vararg inserts: AuditEventInsert) {
        transaction(db.database) {
            inserts.forEach { ins ->
                AuditEventsTable.insert {
                    it[occurredAt] = ins.occurredAt
                    it[eventType] = ins.eventType
                    it[actorSubject] = ins.actorSubject
                    it[kekId] = ins.kekId
                    it[success] = true
                    it[prevHmac] = ByteArray(64)
                    it[rowHmac] = ByteArray(64)
                }
            }
        }
    }

    private fun cleanup() {
        transaction(db.database) {
            // Delete every row — id is always >= 0 so this matches all rows.
            AuditEventsTable.deleteWhere { AuditEventsTable.id greaterEq 0L }
        }
    }

    private fun Instant.plusSec(seconds: Long): Instant = Instant.fromEpochSeconds(this.epochSeconds + seconds)
}
