package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.auth.TestCertificateFactory
import com.shared.security.adapters.inbound.http.auth.TestPeerCertChainAttributeKey
import com.shared.security.adapters.inbound.http.auth.TestPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.installMtlsAuth
import com.shared.security.adapters.inbound.http.dto.ListJwtSigningKeysResponse
import com.shared.security.adapters.inbound.http.dto.ListKeksResponse
import com.shared.security.adapters.inbound.http.dto.ListRecentRotationsResponse
import com.shared.security.adapters.inbound.http.dto.SearchAuditEventsResponse
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import com.shared.security.application.ports.DashboardObserverAllowList
import com.shared.security.application.ports.DekRecord
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import com.shared.security.application.ports.KekLifecycleStatus
import com.shared.security.application.ports.KekRecord
import com.shared.security.application.ports.KekRepository
import com.shared.security.application.usecases.observation.ListDeksObservationUseCase
import com.shared.security.application.usecases.observation.ListJwtSigningKeysObservationUseCase
import com.shared.security.application.usecases.observation.ListKeksObservationUseCase
import com.shared.security.application.usecases.observation.ListRecentRotationsObservationUseCase
import com.shared.security.application.usecases.observation.SearchAuditEventsObservationUseCase
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation

class ObservabilityRoutesTest {
    private val observerDn = "CN=workautomations-dashboard-observer,O=WorkAutomations"
    private val adminDn = "CN=workautomations-admin-1,O=WorkAutomations"

    private fun io.ktor.server.testing.ApplicationTestBuilder.installWiring(
        audit: AuditLogPort,
        allowed: Set<String>,
        cert: X509Certificate,
        keks: List<KekRecord> = emptyList(),
        deks: List<DekRecord> = emptyList(),
        jwtKeys: List<JwtSigningKeyRecord> = emptyList(),
        auditRows: List<AuditLogQueryPort.Row> = emptyList(),
        rateLimiter: PerSubjectRateLimiter? = null,
    ) {
        val kekRepo = StubKekRepo(keks)
        val dekRepo = StubDekRepo(deks)
        val jwtRepo = StubJwtRepo(jwtKeys)
        val auditQuery = StubAuditQuery(auditRows)
        application {
            install(ContentNegotiation) { json() }
            intercept(ApplicationCallPipeline.Setup) {
                context.attributes.put(TestPeerCertChainAttributeKey, arrayOf(cert))
            }
            installMtlsAuth(extractor = TestPeerCertChainExtractor(), auditLog = audit)
            routing {
                installObservabilityRoutes(
                    observerAllowList = DashboardObserverAllowList { it in allowed },
                    auditLog = audit,
                    rateLimiter = rateLimiter,
                    listKeks = ListKeksObservationUseCase(kekRepo, audit),
                    listDeks = ListDeksObservationUseCase(dekRepo, audit),
                    listJwtSigningKeys = ListJwtSigningKeysObservationUseCase(jwtRepo, audit),
                    searchAuditEvents = SearchAuditEventsObservationUseCase(auditQuery, audit),
                    listRecentRotations = ListRecentRotationsObservationUseCase(auditQuery, audit),
                )
            }
        }
    }

    private fun jsonClient(builder: io.ktor.server.testing.ApplicationTestBuilder) =
        builder.createClient { install(ClientContentNegotiation) { json() } }

    @Test
    fun `GET v1 observability keks with observer DN returns rows and writes DASHBOARD_OBSERVED`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                keks = listOf(kek("kek-1", KekLifecycleStatus.ACTIVE, now)),
            )

            val response = jsonClient(this).get("/v1/observability/keks")

            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.body<ListKeksResponse>()
            assertEquals(1, body.keks.size)
            assertEquals("kek-1", body.keks.single().id)
            assertEquals(AuditEventType.DASHBOARD_OBSERVED, audit.events.single().eventType)
        }

    @Test
    fun `GET v1 observability keks with admin DN returns 403 and writes OBSERVER_FORBIDDEN`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = adminDn)
            // allowed set is just the observer DN — the admin DN bounces.
            installWiring(audit, allowed = setOf(observerDn), cert = cert)

            val response = jsonClient(this).get("/v1/observability/keks")

            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertTrue(audit.events.any { it.eventType == AuditEventType.OBSERVER_FORBIDDEN })
        }

    @Test
    fun `GET v1 observability deks omits wrapped bytes from JSON response`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            val handle = ByteArray(16) { it.toByte() }
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                deks =
                    listOf(
                        DekRecord(
                            handle = handle,
                            kekId = "kek-1",
                            // sensitive — must NOT appear in the response body.
                            wrappedDekBytes = ByteArray(64) { 0x42 },
                            createdAt = now,
                            updatedAt = now,
                        ),
                    ),
            )

            val rawBody = jsonClient(this).get("/v1/observability/deks").body<String>()

            assertTrue(!rawBody.contains("wrappedDekBytes"))
            assertTrue(!rawBody.contains("\"wrapped"))
        }

    @Test
    fun `GET v1 observability jwt-signing-keys omits public key bytes`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                jwtKeys =
                    listOf(
                        JwtSigningKeyRecord(
                            kid = ByteArray(16) { 0x9d.toByte() },
                            status = JwtSigningKeyStatus.ACTIVE,
                            algorithm = "ES256",
                            curve = "P-256",
                            wrappedPrivateKeyBytes = ByteArray(96) { 0xAA.toByte() },
                            publicKeySpki = ByteArray(91) { 0xBB.toByte() },
                            wrappedUnderKekId = "kek-1",
                            createdAt = now,
                            activatedAt = now,
                            quiescedAt = null,
                            retiredAt = null,
                            retainUntil = null,
                        ),
                    ),
            )

            val response = jsonClient(this).get("/v1/observability/jwt-signing-keys")
            val body = response.body<ListJwtSigningKeysResponse>()

            assertEquals(1, body.keys.size)
            val rawBody = jsonClient(this).get("/v1/observability/jwt-signing-keys").body<String>()
            assertTrue(!rawBody.contains("wrappedPrivateKey"))
            assertTrue(!rawBody.contains("publicKeySpki"))
        }

    @Test
    fun `GET v1 observability audit-events strips prev_hmac and row_hmac at the port boundary`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                auditRows =
                    listOf(
                        AuditLogQueryPort.Row(
                            id = 1L,
                            occurredAt = now,
                            eventType = "DEK_UNWRAPPED",
                            actorSubject = "CN=monolith",
                            kekId = "kek-1",
                            dekHandle = byteArrayOf(0x01),
                            success = true,
                            detailJson = null,
                        ),
                    ),
            )

            val rawBody = jsonClient(this).get("/v1/observability/audit-events").body<String>()
            val body = jsonClient(this).get("/v1/observability/audit-events").body<SearchAuditEventsResponse>()

            assertEquals(1, body.items.size)
            assertTrue(!rawBody.contains("prev_hmac"))
            assertTrue(!rawBody.contains("row_hmac"))
        }

    @Test
    fun `GET v1 observability recent-rotations returns rotation rows only`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            // Stub query accepts the rotation filter and returns matching rows; the use-case
            // contract enforces the filter set, not the test stub.
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                auditRows =
                    listOf(
                        AuditLogQueryPort.Row(
                            id = 1L,
                            occurredAt = now,
                            eventType = "KEK_ACTIVATED",
                            actorSubject = "CN=admin",
                            kekId = "kek-1",
                            dekHandle = null,
                            success = true,
                            detailJson = null,
                        ),
                    ),
            )

            val response = jsonClient(this).get("/v1/observability/recent-rotations?n=5")
            val body = response.body<ListRecentRotationsResponse>()

            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(1, body.rotations.size)
            assertEquals("KEK_ACTIVATED", body.rotations.single().eventType)
        }

    @Test
    fun `over-cap rate limit returns 429 and writes OBSERVABILITY_RATE_LIMIT_EXCEEDED`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            // Capacity 1 + slow refill — first call drains, second call denied.
            val limiter = PerSubjectRateLimiter(capacity = 1.0, refillTokensPerSecond = 0.0001)
            installWiring(audit, allowed = setOf(cert.subjectX500Principal.name), cert = cert, rateLimiter = limiter)

            val client = jsonClient(this)
            val first = client.get("/v1/observability/keks")
            val second = client.get("/v1/observability/keks")

            assertEquals(HttpStatusCode.OK, first.status)
            assertEquals(HttpStatusCode.TooManyRequests, second.status)
            assertTrue(audit.events.any { it.eventType == AuditEventType.OBSERVABILITY_RATE_LIMIT_EXCEEDED })
        }

    @Test
    fun `audit-events accepts eventTypeFilter and freeText query params`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                auditRows =
                    listOf(
                        AuditLogQueryPort.Row(
                            id = 1L,
                            occurredAt = now,
                            eventType = "JWT_SIGNED",
                            actorSubject = "CN=monolith",
                            kekId = null,
                            dekHandle = null,
                            success = true,
                            detailJson = null,
                        ),
                    ),
            )

            val response =
                jsonClient(this).get(
                    "/v1/observability/audit-events?q=monolith&eventTypeFilter=JWT_SIGNED,KEK_ACTIVATED&page=0&size=10",
                )
            val body = response.body<SearchAuditEventsResponse>()

            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(1, body.items.size)
            assertEquals(0, body.page)
            assertEquals(10, body.pageSize)
        }

    @Test
    fun `request without mTLS principal returns 401`() =
        testApplication {
            // The TestPeerCertChainAttributeKey is not set on the call, so the principal extractor
            // returns null — auth plugin returns 401 before we even hit the route.
            application {
                install(ContentNegotiation) { json() }
                installMtlsAuth(extractor = TestPeerCertChainExtractor(), auditLog = RecordingAuditLog())
                val audit = RecordingAuditLog()
                val emptyKeks = ListKeksObservationUseCase(StubKekRepo(emptyList()), audit)
                val emptyDeks = ListDeksObservationUseCase(StubDekRepo(emptyList()), audit)
                val emptyJwt = ListJwtSigningKeysObservationUseCase(StubJwtRepo(emptyList()), audit)
                val emptyAuditQuery = StubAuditQuery(emptyList())
                val emptySearch = SearchAuditEventsObservationUseCase(emptyAuditQuery, audit)
                val emptyRotations = ListRecentRotationsObservationUseCase(emptyAuditQuery, audit)
                routing {
                    installObservabilityRoutes(
                        observerAllowList = DashboardObserverAllowList { true },
                        auditLog = audit,
                        listKeks = emptyKeks,
                        listDeks = emptyDeks,
                        listJwtSigningKeys = emptyJwt,
                        searchAuditEvents = emptySearch,
                        listRecentRotations = emptyRotations,
                    )
                }
            }

            val response = jsonClient(this).get("/v1/observability/keks")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
        }

    @Test
    fun `unknown observer DN bounces with OBSERVER_FORBIDDEN on every endpoint`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = "CN=unknown,O=WorkAutomations")
            installWiring(audit, allowed = setOf(observerDn), cert = cert)
            val client = jsonClient(this)

            val keks = client.get("/v1/observability/keks").status
            val deks = client.get("/v1/observability/deks").status
            val jwt = client.get("/v1/observability/jwt-signing-keys").status
            val auditEv = client.get("/v1/observability/audit-events").status
            val rotations = client.get("/v1/observability/recent-rotations").status

            assertEquals(HttpStatusCode.Forbidden, keks)
            assertEquals(HttpStatusCode.Forbidden, deks)
            assertEquals(HttpStatusCode.Forbidden, jwt)
            assertEquals(HttpStatusCode.Forbidden, auditEv)
            assertEquals(HttpStatusCode.Forbidden, rotations)
            // 5 forbidden calls → 5 OBSERVER_FORBIDDEN audit rows.
            assertEquals(5, audit.events.count { it.eventType == AuditEventType.OBSERVER_FORBIDDEN })
        }

    @Test
    fun `every successful call writes exactly one DASHBOARD_OBSERVED regardless of row count`() =
        testApplication {
            val now = Clock.System.now()
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            installWiring(
                audit,
                allowed = setOf(cert.subjectX500Principal.name),
                cert = cert,
                keks = (1..20).map { kek("kek-$it", KekLifecycleStatus.RETIRED, now) },
            )

            jsonClient(this).get("/v1/observability/keks")

            assertEquals(1, audit.events.count { it.eventType == AuditEventType.DASHBOARD_OBSERVED })
        }

    @Test
    fun `audit-events page params are reflected on response`() =
        testApplication {
            val audit = RecordingAuditLog()
            val cert = TestCertificateFactory.generate(subjectDn = observerDn)
            installWiring(audit, allowed = setOf(cert.subjectX500Principal.name), cert = cert)

            val response = jsonClient(this).get("/v1/observability/audit-events?page=3&size=25")
            val body = response.body<SearchAuditEventsResponse>()

            assertEquals(3, body.page)
            assertEquals(25, body.pageSize)
        }

    // ---- helpers ----

    private fun kek(
        id: String,
        status: KekLifecycleStatus,
        now: Instant,
    ): KekRecord =
        KekRecord(
            id = id,
            fingerprint = "fp:$id",
            status = status,
            createdAt = now,
            activatedAt = if (status != KekLifecycleStatus.STAGED) now else null,
            quiescedAt = null,
            retiredAt = if (status == KekLifecycleStatus.RETIRED) now else null,
        )

    private class StubKekRepo(private val all: List<KekRecord>) : KekRepository {
        override suspend fun findActive(): KekRecord? = all.firstOrNull { it.status == KekLifecycleStatus.ACTIVE }

        override suspend fun findAllPrior(): List<KekRecord> = all.filter { it.status == KekLifecycleStatus.PRIOR }

        override suspend fun findById(id: String): KekRecord? = all.firstOrNull { it.id == id }

        override suspend fun retirePrior(id: String): Boolean = error("not used")

        override suspend fun findAll(): List<KekRecord> = all
    }

    private class StubDekRepo(private val all: List<DekRecord>) : DekRepository {
        override suspend fun countByKekId(kekId: String): Long = error("not used")

        override suspend fun findBatchByKekId(
            kekId: String,
            limit: Int,
        ): List<DekRecord> = error("not used")

        override suspend fun rewrap(
            handle: ByteArray,
            newKekId: String,
            newWrappedBytes: ByteArray,
            updatedAt: Instant,
        ): Boolean = error("not used")

        override suspend fun findRecent(limit: Int): List<DekRecord> = all.take(limit)

        override suspend fun countAll(): Long = all.size.toLong()
    }

    private class StubJwtRepo(private val all: List<JwtSigningKeyRecord>) : JwtSigningKeyRepository {
        override suspend fun findActive(): JwtSigningKeyRecord? {
            return all.firstOrNull { it.status == JwtSigningKeyStatus.ACTIVE }
        }

        override suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord> = emptyList()

        override suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord? = null

        override suspend fun findAllPublishable(): List<JwtSigningKeyRecord> = emptyList()

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

        override suspend fun findRetiredEligibleForDelete(now: Instant): List<JwtSigningKeyRecord> = emptyList()

        override suspend fun findAll(): List<JwtSigningKeyRecord> = all
    }

    private class StubAuditQuery(private val rows: List<AuditLogQueryPort.Row>) : AuditLogQueryPort {
        override suspend fun search(
            freeText: String?,
            eventTypeIn: Set<String>?,
            fromTime: Instant?,
            toTime: Instant?,
            page: Int,
            size: Int,
        ): AuditLogQueryPort.SearchResult {
            return AuditLogQueryPort.SearchResult(rows = rows, totalCount = rows.size.toLong())
        }
    }

    private class RecordingAuditLog : AuditLogPort {
        val events = mutableListOf<AuditEvent>()

        override suspend fun write(event: AuditEvent) {
            events += event
        }
    }

    @Suppress("unused")
    private fun forceNullReference(): String? = null.also { assertNull(it) }
}
