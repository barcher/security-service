package com.shared.security.adapters.outbound.persistence

import com.shared.security.domain.oauth.AuthorizationCode
import com.shared.security.domain.oauth.OAuthClient
import com.shared.security.domain.oauth.OAuthClientAuthMethod
import com.shared.security.domain.oauth.OAuthGrantType
import com.shared.security.domain.oauth.OAuthScope
import com.shared.security.domain.oauth.PkceChallengeMethod
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
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

@Tag("integration")
@TestInstance(Lifecycle.PER_CLASS)
class OAuthPersistenceMigrationTest {
    private lateinit var mysql: MySQLContainer<*>
    private lateinit var db: SecurityDatabase
    private lateinit var clients: ExposedOAuthClientRepository
    private lateinit var codes: ExposedAuthorizationCodeRepository

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
        clients = ExposedOAuthClientRepository(db.database)
        codes = ExposedAuthorizationCodeRepository(db.database)
    }

    @AfterAll
    fun tearDown() {
        db.close()
        mysql.stop()
    }

    @Test
    fun `V9 oauth_clients round-trips and insertIfAbsent is idempotent`() =
        runTest {
            val client =
                OAuthClient(
                    clientId = "workautomations-financial",
                    authMethod = OAuthClientAuthMethod.TLS_CLIENT_AUTH,
                    subjectDn = "CN=workautomations-financial-monolith,O=WorkAutomations",
                    allowedGrantTypes = setOf(OAuthGrantType.CLIENT_CREDENTIALS),
                    allowedScopes = setOf(OAuthScope.of("crypto.dek"), OAuthScope.OPENID),
                    allowedAudiences = setOf("workautomations-api"),
                    enabled = true,
                )

            assertTrue(clients.insertIfAbsent(client))
            // Re-seed is a no-op.
            assertFalse(clients.insertIfAbsent(client))

            val byId = clients.findByClientId("workautomations-financial")
            assertNotNull(byId)
            assertEquals(client.subjectDn, byId!!.subjectDn)
            assertEquals(client.allowedGrantTypes, byId.allowedGrantTypes)
            assertEquals(client.allowedScopes, byId.allowedScopes)
            assertEquals(client.allowedAudiences, byId.allowedAudiences)

            val byDn = clients.findBySubjectDn(client.subjectDn!!)
            assertEquals("workautomations-financial", byDn?.clientId)
        }

    @Test
    fun `V10 authorization_codes round-trips and markRedeemed enforces single use`() =
        runTest {
            // FK to oauth_clients — seed the client first.
            val clientId = "workautomations-frontend"
            clients.insertIfAbsent(
                OAuthClient(
                    clientId = clientId,
                    authMethod = OAuthClientAuthMethod.NONE,
                    subjectDn = null,
                    allowedGrantTypes = setOf(OAuthGrantType.AUTHORIZATION_CODE),
                    allowedScopes = setOf(OAuthScope.OPENID),
                    allowedAudiences = setOf("workautomations-api"),
                    enabled = true,
                ),
            )

            val now: Instant = Clock.System.now()
            val hash = ByteArray(32) { 0x5A.toByte() }
            val code =
                AuthorizationCode(
                    codeHash = hash,
                    clientId = clientId,
                    subject = "user-123",
                    redirectUri = "https://app.example/callback",
                    codeChallenge = "abc123challenge",
                    codeChallengeMethod = PkceChallengeMethod.S256,
                    scopes = setOf(OAuthScope.OPENID),
                    issuedAt = now,
                    expiresAt = now,
                )
            codes.insert(code)

            val read = codes.findByHash(hash)
            assertNotNull(read)
            assertEquals(clientId, read!!.clientId)
            assertEquals("user-123", read.subject)
            assertNull(read.redeemedAt)

            // First redeem succeeds; second is rejected (single-use).
            assertTrue(codes.markRedeemed(hash))
            assertFalse(codes.markRedeemed(hash))
            assertTrue(codes.findByHash(hash)!!.isRedeemed())
        }
}
