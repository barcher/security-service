package com.shared.security.infrastructure

import com.shared.security.adapters.outbound.crypto.KekEnvelopeAdapter
import com.shared.security.adapters.outbound.crypto.MlKemCryptoKeyService
import com.shared.security.adapters.outbound.jwtsigning.Es256JwtSigningKeyAdapter
import com.shared.security.adapters.outbound.persistence.ExposedJwtSigningKeyRepository
import com.shared.security.adapters.outbound.persistence.ExposedKekRepository
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.adapters.outbound.persistence.tables.KekStatus
import com.shared.security.adapters.outbound.persistence.tables.KeksTable
import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtAudienceAllowList
import com.shared.security.application.usecases.jwt.ActivateJwtSigningKeyUseCase
import com.shared.security.application.usecases.jwt.GenerateJwtSigningKeyPairUseCase
import com.shared.security.application.usecases.jwt.SignJwtUseCase
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
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
import java.util.Base64
import java.util.UUID

/**
 * End-to-end test of the Stream K K.0 happy path:
 *   1. Bring up MySQL + run Flyway V1..V5 migrations.
 *   2. Seed a single ACTIVE KEK row using ML-KEM-768 material.
 *   3. Mint a fresh ES256 signing keypair via `GenerateJwtSigningKeyPairUseCase` (wraps
 *      under the KEK via the internal `KekEnvelopePort` ↔ `KekEnvelopeAdapter` bridge).
 *   4. Activate the keypair via `ActivateJwtSigningKeyUseCase`.
 *   5. Mint a JWT via `SignJwtUseCase` against an allow-listed audience.
 *   6. Locally verify the JWT signature against the SPKI public key fetched from the
 *      repository — proves the wrap → unwrap → sign → verify chain is intact.
 */
@Tag("integration")
@TestInstance(Lifecycle.PER_CLASS)
class JwtSignAndJwksIntegrationTest {
    private lateinit var mysql: MySQLContainer<*>
    private lateinit var db: SecurityDatabase
    private val testSubjectDn = "CN=integration-test,O=WorkAutomations"
    private val testAudience = "workautomations-api"

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
    fun `generate activate sign and locally verify happy path`() =
        runTest {
            // Seed an ACTIVE KEK row backed by a freshly-generated ML-KEM keypair.
            val kekPair = MlKemCryptoKeyService.generateBootstrapKekPair()
            val kekId = seedActiveKek(fingerprint = "fp:" + UUID.randomUUID())
            val crypto = MlKemCryptoKeyService.fromBase64(kekPair.publicKeyB64, kekPair.privateKeyB64)
            val kekRepo = ExposedKekRepository(db.database)
            val kekEnvelope = KekEnvelopeAdapter(crypto, kekRepo)
            val signing = Es256JwtSigningKeyAdapter()
            val jwtRepo = ExposedJwtSigningKeyRepository(db.database)
            val audit = CollectingAuditLog()

            // Step 1: generate STAGED keypair.
            val generate = GenerateJwtSigningKeyPairUseCase(signing, kekEnvelope, jwtRepo, audit)
            val staged = generate.execute(actorSubject = "operator:test")
            assertEquals(kekId, staged.wrappedUnderKekId, "JWT key should wrap under the ACTIVE KEK")

            // Step 2: activate it.
            val activate = ActivateJwtSigningKeyUseCase(jwtRepo, audit)
            val activateResult = activate.execute(staged.kid, actorSubject = "operator:test")
            assertEquals(ActivateJwtSigningKeyUseCase.Result.Activated, activateResult)
            assertNotNull(jwtRepo.findActive())

            // Step 3: mint a JWT against an allow-listed audience.
            val allowList =
                object : JwtAudienceAllowList {
                    override fun isAllowed(
                        subjectDn: String,
                        audience: String,
                    ): Boolean = subjectDn == testSubjectDn && audience == testAudience
                }
            val signJwt =
                SignJwtUseCase(
                    repo = jwtRepo,
                    kekEnvelope = kekEnvelope,
                    signing = signing,
                    audienceAllowList = allowList,
                    auditLog = audit,
                )
            val result =
                signJwt.execute(
                    SignJwtUseCase.Request(
                        subjectDn = testSubjectDn,
                        subject = "user-42",
                        audience = testAudience,
                        issuer = "security-service",
                        expiresInSeconds = 300,
                    ),
                )

            assertTrue(result is SignJwtUseCase.Result.Signed)
            val signed = result as SignJwtUseCase.Result.Signed
            val parts = signed.token.split(".")
            assertEquals(3, parts.size)

            // Step 4: locally verify the signature using the stored public key.
            val activeKey = jwtRepo.findActive()!!
            val signingInput = (parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII)
            val sigBytes = Base64.getUrlDecoder().decode(parts[2])
            val ok = signing.verify(activeKey.publicKeySpki, signingInput, sigBytes)
            assertTrue(ok, "JWT signature must verify locally against the stored SPKI")

            // Step 5: confirm the audit chain captured the lifecycle events we care about.
            val eventTypes = audit.events.map { it.eventType }
            assertTrue(eventTypes.contains("JWKS_KEY_GENERATED"))
            assertTrue(eventTypes.contains("JWKS_KEY_ACTIVATED"))
            assertTrue(eventTypes.contains("JWT_SIGNED"))
        }

    @Test
    fun `audience not allow-listed fails Gate-2 without minting`() =
        runTest {
            val kekPair = MlKemCryptoKeyService.generateBootstrapKekPair()
            seedActiveKek(fingerprint = "fp:" + UUID.randomUUID())
            val crypto = MlKemCryptoKeyService.fromBase64(kekPair.publicKeyB64, kekPair.privateKeyB64)
            val kekRepo = ExposedKekRepository(db.database)
            val kekEnvelope = KekEnvelopeAdapter(crypto, kekRepo)
            val signing = Es256JwtSigningKeyAdapter()
            val jwtRepo = ExposedJwtSigningKeyRepository(db.database)
            val audit = CollectingAuditLog()

            val generate = GenerateJwtSigningKeyPairUseCase(signing, kekEnvelope, jwtRepo, audit)
            val staged = generate.execute(actorSubject = "operator:test")
            ActivateJwtSigningKeyUseCase(jwtRepo, audit).execute(staged.kid, actorSubject = "operator:test")

            val denyAll =
                object : JwtAudienceAllowList {
                    override fun isAllowed(
                        subjectDn: String,
                        audience: String,
                    ): Boolean = false
                }
            val signJwt =
                SignJwtUseCase(
                    repo = jwtRepo,
                    kekEnvelope = kekEnvelope,
                    signing = signing,
                    audienceAllowList = denyAll,
                    auditLog = audit,
                )
            val result =
                signJwt.execute(
                    SignJwtUseCase.Request(
                        subjectDn = "CN=other",
                        subject = "user-99",
                        audience = "forbidden",
                        issuer = "security-service",
                        expiresInSeconds = 60,
                    ),
                )
            assertEquals(SignJwtUseCase.Result.AudienceForbidden, result)
            val forbiddenEvents = audit.events.filter { it.eventType == "JWT_AUDIENCE_FORBIDDEN" }
            assertEquals(1, forbiddenEvents.size)
        }

    private fun seedActiveKek(fingerprint: String): String {
        val id = UUID.randomUUID().toString()
        transaction(db.database) {
            // Demote any existing ACTIVE row so the singleton invariant holds.
            KeksTable.update({ KeksTable.status eq KekStatus.ACTIVE }) {
                it[status] = KekStatus.PRIOR
                it[quiescedAt] = Clock.System.now()
            }
            KeksTable.insert {
                it[KeksTable.id] = id
                it[KeksTable.fingerprint] = fingerprint
                it[status] = KekStatus.ACTIVE
                it[createdAt] = Clock.System.now()
                it[activatedAt] = Clock.System.now()
            }
        }
        return id
    }

    private class CollectingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events.add(event)
        }
    }
}
