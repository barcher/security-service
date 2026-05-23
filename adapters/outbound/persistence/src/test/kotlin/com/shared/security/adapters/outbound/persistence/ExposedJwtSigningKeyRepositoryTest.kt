package com.shared.security.adapters.outbound.persistence

import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyStatus
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle
import org.testcontainers.containers.MySQLContainer
import java.util.UUID
import kotlin.random.Random

@Tag("integration")
@TestInstance(Lifecycle.PER_CLASS)
class ExposedJwtSigningKeyRepositoryTest {
    private lateinit var mysql: MySQLContainer<*>
    private lateinit var db: SecurityDatabase
    private lateinit var repo: ExposedJwtSigningKeyRepository

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
        repo = ExposedJwtSigningKeyRepository(db.database)
    }

    @AfterAll
    fun tearDown() {
        db.close()
        mysql.stop()
    }

    @Test
    fun `insertStaged then activate transitions the row to ACTIVE`() =
        runTest {
            val rec = stagedRecord()
            repo.insertStaged(rec)
            assertNull(repo.findActive())

            val now = Clock.System.now()
            val ok = repo.activate(rec.kid, now)
            assertTrue(ok)

            val active = repo.findActive()
            assertNotNull(active)
            assertEquals(JwtSigningKeyStatus.ACTIVE, active!!.status)
            assertEquals(now, active.activatedAt)
            assertEquals(rec.publicKeySpki.toList(), active.publicKeySpki.toList())
        }

    @Test
    fun `activate demotes existing ACTIVE row to PRIOR then promotes new STAGED`() =
        runTest {
            val first = stagedRecord()
            val second = stagedRecord()
            repo.insertStaged(first)
            repo.insertStaged(second)

            repo.activate(first.kid, Clock.System.now())
            assertEquals(JwtSigningKeyStatus.ACTIVE, repo.findByKid(first.kid)!!.status)

            repo.activate(second.kid, Clock.System.now())
            assertEquals(JwtSigningKeyStatus.PRIOR, repo.findByKid(first.kid)!!.status)
            assertEquals(JwtSigningKeyStatus.ACTIVE, repo.findByKid(second.kid)!!.status)

            val active = repo.findActive()
            assertNotNull(active)
            assertEquals(second.kid.toList(), active!!.kid.toList())
        }

    @Test
    fun `findAllPublishable returns ACTIVE then PRIOR in deterministic order`() =
        runTest {
            val active = stagedRecord().also { repo.insertStaged(it) }
            val prior = stagedRecord().also { repo.insertStaged(it) }
            repo.activate(prior.kid, Clock.System.now())
            repo.activate(active.kid, Clock.System.now())

            val publishable = repo.findAllPublishable()
            assertEquals(2, publishable.size)
            assertEquals(JwtSigningKeyStatus.ACTIVE, publishable[0].status)
            assertEquals(active.kid.toList(), publishable[0].kid.toList())
            assertEquals(JwtSigningKeyStatus.PRIOR, publishable[1].status)
            assertEquals(prior.kid.toList(), publishable[1].kid.toList())
        }

    @Test
    fun `lifecycle PRIOR to QUIESCED to RETIRED honors status guards`() =
        runTest {
            val rec = stagedRecord().also { repo.insertStaged(it) }
            repo.activate(rec.kid, Clock.System.now())

            // PRIOR is reached by activating a different key.
            val other = stagedRecord().also { repo.insertStaged(it) }
            repo.activate(other.kid, Clock.System.now())

            // quiescePrior on a PRIOR row succeeds; on a non-PRIOR row returns false.
            assertTrue(repo.quiescePrior(rec.kid, Clock.System.now()))
            assertFalse(repo.quiescePrior(other.kid, Clock.System.now())) // still ACTIVE

            // retireQuiesced sets retain_until = now + retentionDays.
            val retireAt = Clock.System.now()
            assertTrue(repo.retireQuiesced(rec.kid, retireAt, retentionDays = 7))
            val retired = repo.findByKid(rec.kid)!!
            assertEquals(JwtSigningKeyStatus.RETIRED, retired.status)
            assertNotNull(retired.retainUntil)

            // deleteRetired only succeeds on RETIRED rows.
            assertTrue(repo.deleteRetired(rec.kid))
            assertNull(repo.findByKid(rec.kid))
        }

    private fun stagedRecord(): JwtSigningKeyRecord =
        JwtSigningKeyRecord(
            kid = Random.nextBytes(16),
            status = JwtSigningKeyStatus.STAGED,
            algorithm = "ES256",
            curve = "P-256",
            wrappedPrivateKeyBytes = Random.nextBytes(96),
            publicKeySpki = Random.nextBytes(91),
            wrappedUnderKekId = UUID.randomUUID().toString(),
            createdAt = Clock.System.now(),
            activatedAt = null,
            quiescedAt = null,
            retiredAt = null,
            retainUntil = null,
        )
}
