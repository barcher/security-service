package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.dto.JwksResponseDto
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import com.shared.security.application.usecases.jwt.GeneratedKeyPair
import com.shared.security.application.usecases.jwt.JwkCoords
import com.shared.security.application.usecases.jwt.JwtSigningKeyPort
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation

class JwksRoutesTest {
    private class StubRepo(private val rows: List<JwtSigningKeyRecord>) : JwtSigningKeyRepository {
        override suspend fun findAllPublishable(): List<JwtSigningKeyRecord> = rows

        override suspend fun findActive(): JwtSigningKeyRecord? = error("not used")

        override suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord> = error("not used")

        override suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord? = error("not used")

        override suspend fun insertStaged(record: JwtSigningKeyRecord) = error("not used")

        override suspend fun activate(
            kid: ByteArray,
            now: Instant,
        ): Boolean = error("not used")

        override suspend fun quiescePrior(
            kid: ByteArray,
            now: Instant,
        ): Boolean = error("not used")

        override suspend fun retireQuiesced(
            kid: ByteArray,
            now: Instant,
            retentionDays: Long,
        ): Boolean = error("not used")

        override suspend fun deleteRetired(kid: ByteArray): Boolean = error("not used")

        override suspend fun findRetiredEligibleForDelete(now: Instant): List<JwtSigningKeyRecord> = error("not used")

        override suspend fun findAll(): List<JwtSigningKeyRecord> = error("not used")
    }

    private class StubSigning : JwtSigningKeyPort {
        override fun spkiToJwkXY(publicKeySpki: ByteArray): JwkCoords = JwkCoords(x = "X-coord", y = "Y-coord")

        override fun generateKeyPair(): GeneratedKeyPair = error("not used")

        override fun sign(
            privateKeyPkcs8: ByteArray,
            payload: ByteArray,
        ): ByteArray = error("not used")

        override fun verify(
            publicKeySpki: ByteArray,
            payload: ByteArray,
            signature: ByteArray,
        ): Boolean = error("not used")

        override fun computeKid(publicKeySpki: ByteArray): ByteArray = error("not used")
    }

    private fun fakeRecord(): JwtSigningKeyRecord =
        JwtSigningKeyRecord(
            kid = byteArrayOf(0xAB.toByte(), 0xCD.toByte()),
            status = JwtSigningKeyStatus.ACTIVE,
            algorithm = "ES256",
            curve = "P-256",
            wrappedPrivateKeyBytes = ByteArray(0),
            publicKeySpki = ByteArray(0),
            wrappedUnderKekId = "kek-0",
            createdAt = Clock.System.now(),
            activatedAt = Clock.System.now(),
            quiescedAt = null,
            retiredAt = null,
            retainUntil = null,
        )

    private fun ApplicationTestBuilder.installWiring(
        repo: JwtSigningKeyRepository,
        rateLimiter: PerSubjectRateLimiter? = null,
    ) {
        application {
            install(ContentNegotiation) { json() }
            routing {
                installJwksRoutes(repo = repo, signing = StubSigning(), rateLimiter = rateLimiter)
            }
        }
    }

    private fun ApplicationTestBuilder.jsonClient() = createClient { install(ClientContentNegotiation) { json() } }

    @Test
    fun `GET v1 jwks returns 200 with the publishable key set and cache header`() =
        testApplication {
            installWiring(repo = StubRepo(listOf(fakeRecord())))

            val response = jsonClient().get("/v1/jwks")

            assertEquals(HttpStatusCode.OK, response.status)
            val cache = response.headers[HttpHeaders.CacheControl]
            assertTrue(cache?.contains("max-age=300") == true, "expected 5-min cache header, got: $cache")
            val body = response.body<JwksResponseDto>()
            assertEquals(1, body.keys.size)
            assertEquals("X-coord", body.keys.first().x)
            assertEquals("Y-coord", body.keys.first().y)
            // kid: 0xAB 0xCD → "abcd"
            assertEquals("abcd", body.keys.first().kid)
        }

    @Test
    fun `route is reachable without any client cert (no MtlsAuthPlugin installed)`() =
        testApplication {
            // Note: this test wires routing only, without installMtlsAuth — proving that
            // the route itself doesn't require auth. The Application.kt prod wiring still
            // adds the global MtlsAuthPlugin interceptor with `/v1/jwks` on the public
            // allow-list; MtlsAuthPluginTest covers that path explicitly.
            installWiring(repo = StubRepo(emptyList()))

            val response = jsonClient().get("/v1/jwks")

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<JwksResponseDto>()
            assertEquals(0, body.keys.size)
        }

    @Test
    fun `rate limiter enforces 429 after capacity is exhausted (per remote host)`() =
        testApplication {
            // capacity=2, refill=very slow → third call within the test window is rejected.
            val limiter = PerSubjectRateLimiter(capacity = 2.0, refillTokensPerSecond = 0.001)
            installWiring(repo = StubRepo(listOf(fakeRecord())), rateLimiter = limiter)
            val client = jsonClient()

            val first = client.get("/v1/jwks")
            val second = client.get("/v1/jwks")
            val third = client.get("/v1/jwks")

            assertEquals(HttpStatusCode.OK, first.status)
            assertEquals(HttpStatusCode.OK, second.status)
            assertEquals(HttpStatusCode.TooManyRequests, third.status)
            assertTrue(third.bodyAsText().contains("rate_limit_exceeded"))
        }

    @Test
    fun `passing a null rate limiter disables the limit`() =
        testApplication {
            installWiring(repo = StubRepo(listOf(fakeRecord())), rateLimiter = null)
            val client = jsonClient()

            repeat(5) {
                val response = client.get("/v1/jwks")
                assertEquals(HttpStatusCode.OK, response.status)
            }
        }
}
