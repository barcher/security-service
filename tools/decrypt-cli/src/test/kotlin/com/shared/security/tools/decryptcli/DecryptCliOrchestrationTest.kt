package com.shared.security.tools.decryptcli

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import com.shared.security.application.ports.DekRecord
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

class DecryptCliOrchestrationTest {
    @Test
    fun `audit row is emitted before unwrap and contains operator metadata`() {
        val (runtime, recordedAudits) = buildRuntime().let { it.runtime to it.audits }
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 row inspection lookup",
                "--key-handle",
                "ab12cd34",
                "--dry-run",
            )
        val args = parseCliArgs(argv)

        val exit = runCli(args, argv, runtime, fixedClock("2026-05-24T08:00:00Z"))

        assertEquals(0, exit)
        assertEquals(1, recordedAudits.size, "exactly one OPERATOR_DECRYPT_RUN per invocation")
        val audit = recordedAudits.single()
        assertEquals(AuditEventType.OPERATOR_DECRYPT_RUN, audit.eventType)
        assertTrue(audit.success)
        val expectedDn = CertSubjectDnValidator.expectedSubjectDn("ops-alice@example.com")
        assertEquals(expectedDn, audit.actorSubject)
        assertNotNull(audit.detailJson)
        // detail_json must NOT contain plaintext bytes
        val detail = audit.detailJson!!
        assertTrue(detail.contains("operator_email"))
        assertTrue(detail.contains("argument_vector"))
        assertTrue(detail.contains("schema_version"))
    }

    @Test
    fun `hard cap rejection short-circuits before audit emission`() {
        val (runtime, recordedAudits) = buildRuntime().let { it.runtime to it.audits }
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 row inspection lookup",
                "--ids",
                (1..15_000).joinToString(",") { "pk-$it" },
            )
        val args = parseCliArgs(argv)

        val exit = runCli(args, argv, runtime, fixedClock("2026-05-24T08:00:00Z"))

        assertEquals(65, exit, "hard cap exit code")
        assertEquals(0, recordedAudits.size, "audit row MUST NOT be written when hard cap rejects")
    }

    @Test
    fun `dry run emits the invocation envelope but no rows`() {
        val stdout = ByteArrayOutputStream()
        val (runtime, _) =
            buildRuntime(stdoutStream = PrintStream(stdout)).let { it.runtime to it.audits }
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 row inspection lookup",
                "--key-handle",
                "ab12cd34",
                "--dry-run",
            )
        val args = parseCliArgs(argv)

        runCli(args, argv, runtime, fixedClock("2026-05-24T08:00:00Z"))

        val out = stdout.toString(Charsets.UTF_8)
        assertTrue(out.contains("\"row_count\": 0"))
        assertTrue(out.contains("\"dry_run\": true"))
        assertTrue(out.contains("\"side\": \"security-service\""))
    }

    @Test
    fun `audit-event-id scope reads from AuditLogQueryPort`() {
        val recordedAudits = mutableListOf<AuditEvent>()
        val auditLog = collectingAuditLog(recordedAudits)
        val auditQuery =
            object : AuditLogQueryPort {
                override suspend fun search(
                    freeText: String?,
                    eventTypeIn: Set<String>?,
                    fromTime: Instant?,
                    toTime: Instant?,
                    page: Int,
                    size: Int,
                ): AuditLogQueryPort.SearchResult = AuditLogQueryPort.SearchResult(emptyList(), 0L)

                override suspend fun findById(id: Long): AuditLogQueryPort.Row? =
                    if (id == 42L) {
                        AuditLogQueryPort.Row(
                            id = 42L,
                            occurredAt = Instant.parse("2026-05-23T12:00:00Z"),
                            eventType = "DEK_UNWRAPPED",
                            actorSubject = "CN=workautomations-monolith,O=WorkAutomations",
                            kekId = "kek-1",
                            dekHandle = null,
                            success = true,
                            detailJson = "{\"correlation_id\":\"x\"}",
                        )
                    } else {
                        null
                    }
            }
        val runtime =
            CliRuntime(
                auditLog = auditLog,
                auditLogQuery = auditQuery,
                dekRepository = emptyDekRepository(),
                jwtRepository = emptyJwtRepository(),
                stdout = PrintStream(ByteArrayOutputStream()),
            )
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 row inspection lookup",
                "--audit-event-id",
                "42",
            )
        val args = parseCliArgs(argv)

        val exit = runCli(args, argv, runtime, fixedClock("2026-05-24T08:00:00Z"))
        assertEquals(0, exit)
        val audit = recordedAudits.single()
        assertTrue(audit.detailJson!!.contains("\"row_count\":1"))
    }

    // ──── fixtures ────────────────────────────────────────────────────────────

    private data class RuntimeBundle(
        val runtime: CliRuntime,
        val audits: MutableList<AuditEvent>,
    )

    @Suppress("LongParameterList")
    private fun buildRuntime(
        stdoutStream: PrintStream = PrintStream(ByteArrayOutputStream()),
        stderrStream: PrintStream = PrintStream(ByteArrayOutputStream()),
    ): RuntimeBundle {
        val recorded = mutableListOf<AuditEvent>()
        val runtime =
            CliRuntime(
                auditLog = collectingAuditLog(recorded),
                auditLogQuery = noopQuery(),
                dekRepository = emptyDekRepository(),
                jwtRepository = emptyJwtRepository(),
                stdout = stdoutStream,
                stderr = stderrStream,
            )
        return RuntimeBundle(runtime, recorded)
    }

    private fun collectingAuditLog(into: MutableList<AuditEvent>): AuditLogPort =
        object : AuditLogPort {
            override suspend fun write(event: AuditEvent) {
                into.add(event)
            }
        }

    private fun noopQuery(): AuditLogQueryPort =
        object : AuditLogQueryPort {
            override suspend fun search(
                freeText: String?,
                eventTypeIn: Set<String>?,
                fromTime: Instant?,
                toTime: Instant?,
                page: Int,
                size: Int,
            ): AuditLogQueryPort.SearchResult = AuditLogQueryPort.SearchResult(emptyList(), 0L)

            override suspend fun findById(id: Long): AuditLogQueryPort.Row? = null
        }

    private fun emptyDekRepository(): DekRepository =
        object : DekRepository {
            override suspend fun countByKekId(kekId: String): Long = 0L

            override suspend fun findBatchByKekId(
                kekId: String,
                limit: Int,
            ): List<DekRecord> = emptyList()

            override suspend fun rewrap(
                handle: ByteArray,
                newKekId: String,
                newWrappedBytes: ByteArray,
                updatedAt: Instant,
            ): Boolean = false

            override suspend fun findRecent(limit: Int): List<DekRecord> = emptyList()

            override suspend fun countAll(): Long = 0L
        }

    private fun emptyJwtRepository(): JwtSigningKeyRepository =
        object : JwtSigningKeyRepository {
            override suspend fun findActive(): JwtSigningKeyRecord? = null

            override suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord> = emptyList()

            override suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord? = null

            override suspend fun findAllPublishable(): List<JwtSigningKeyRecord> = emptyList()

            override suspend fun insertStaged(record: JwtSigningKeyRecord) = error("not used")

            override suspend fun activate(
                kid: ByteArray,
                now: Instant,
            ): Boolean = false

            override suspend fun quiescePrior(
                kid: ByteArray,
                now: Instant,
            ): Boolean = false

            override suspend fun retireQuiesced(
                kid: ByteArray,
                now: Instant,
                retentionDays: Long,
            ): Boolean = false

            override suspend fun deleteRetired(kid: ByteArray): Boolean = false

            override suspend fun findRetiredEligibleForDelete(now: Instant): List<JwtSigningKeyRecord> = emptyList()

            override suspend fun findAll(): List<JwtSigningKeyRecord> = emptyList()
        }

    private fun fixedClock(iso: String): Clock =
        object : Clock {
            override fun now(): Instant = Instant.parse(iso)
        }
}
