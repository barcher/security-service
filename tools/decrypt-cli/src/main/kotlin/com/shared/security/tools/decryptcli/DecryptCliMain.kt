package com.shared.security.tools.decryptcli

import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.AuditLogQueryPort
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.JwtSigningKeyRepository
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlin.system.exitProcess

/**
 * Phase 14 Stream M (SKS-M05 / SKS-M11) — operator decrypt CLI entry point.
 *
 * **Scope (single-sided per `feedback_operator_decrypt_cli_single_sided.md`):** the
 * security-service CLI is the ONLY operator decrypt CLI in either repo. It targets
 * security-service-owned ciphertext:
 *
 *   * `security_keys.deks.wrapped_dek_bytes` — return the wrapped envelope for
 *     incident response.
 *   * `security_keys.jwt_signing_keys.wrapped_private_key_bytes` (post-Stream-K) —
 *     return the wrapped envelope (full unwrap via `KekEnvelopePort` is a follow-up
 *     ticket; v1.0 emits the envelope so an incident responder can stash it for
 *     offline forensics).
 *   * `security_keys.audit_events.detail_json` — currently plaintext; the
 *     executor exists so future encrypted detail_json drops in cleanly.
 *
 * **NEVER bundled into the running `security-app` docker image** (CLAUDE.md rule 24).
 * **NEVER reachable via HTTP** (CLAUDE.md rule 24, ArchUnit S-15).
 * **Every invocation emits exactly one `OPERATOR_DECRYPT_RUN` audit row** BEFORE any
 * unwrap (CLAUDE.md rule 26).
 *
 * Exit codes:
 *   * 0   — success
 *   * 64  — usage error (bad args)
 *   * 65  — data error (hard cap exceeded without override)
 *   * 70  — software error (unexpected internal failure)
 *
 * Wiring: this `main()` lazily constructs the production DI graph from
 * `CliRuntime.bootProduction()`, which boots a JDBC pool against the security-service
 * MySQL using the same env-var conventions as the running service.  Unit tests
 * instead pass a hand-rolled [CliRuntime] with stub ports so the orchestration is
 * testable without a DB.
 */
fun main(argv: Array<String>) {
    if (argv.isEmpty() || argv[0] == "--help" || argv[0] == "-h") {
        System.out.println(HELP_TEXT)
        exitProcess(0)
    }
    val args =
        try {
            parseCliArgs(argv)
        } catch (e: CliArgsParseException) {
            System.err.println("decrypt-cli: ${e.message}")
            exitProcess(USAGE_EXIT)
        }
    val runtime =
        try {
            CliRuntime.bootProduction()
        } catch (e: IllegalStateException) {
            System.err.println("decrypt-cli: failed to boot runtime: ${e.message}")
            exitProcess(SOFTWARE_EXIT)
        }
    val exitCode = runCli(args, argv, runtime, Clock.System)
    exitProcess(exitCode)
}

/**
 * Test-friendly orchestration entry. Returns the would-be process exit code instead
 * of calling `exitProcess`. Pure function over the runtime + args + clock.
 */
internal fun runCli(
    args: CliArgs,
    argv: Array<String>,
    runtime: CliRuntime,
    clock: Clock,
): Int =
    runBlocking {
        val startedAt = clock.now()
        val spanHours = parseSpanHours(args)
        val rowCountEstimate: Long =
            when (val scope = args.scope) {
                is CliArgs.Scope.KeyHandle -> 1L
                is CliArgs.Scope.AuditEventId -> 1L
                is CliArgs.Scope.Ids -> scope.pks.size.toLong()
                is CliArgs.Scope.TimeWindow -> 0L
            }
        val capOutcome =
            HardCapEnforcer.check(rowCountEstimate, spanHours, args.iUnderstandLargeExport)
        if (capOutcome is HardCapEnforcer.Outcome.CapExceeded) {
            System.err.println("decrypt-cli: ${capOutcome.reason}")
            return@runBlocking HARD_CAP_EXIT
        }

        val tablesUsed = tablesFor(args)
        runtime.audit.writePreRun(args, argv, startedAt, rowCountEstimate, tablesUsed)

        val rows: List<OperatorDecryptOutput.DecryptedRow> =
            if (args.dryRun) {
                emptyList()
            } else {
                executeScope(args.scope, runtime)
            }

        val invocation =
            OperatorDecryptOutput.Invocation(
                operatorEmail = args.operatorEmail,
                reason = args.reason,
                argumentVector = argv.toList(),
                correlationId = args.correlationId,
                startedAt = startedAt,
                finishedAt = clock.now(),
                dryRun = args.dryRun,
                iUnderstandLargeExport = args.iUnderstandLargeExport,
                iAcceptPlaintextOnDisk = args.iAcceptPlaintextOnDisk,
                outputDestination = args.outputDestination,
            )
        val document = OperatorDecryptOutput.Document(invocation = invocation, rows = rows)

        val destination =
            args.outputFile?.let { java.io.PrintStream(java.io.FileOutputStream(it)) }
                ?: runtime.stdout
        runtime.output.render(document, args.output, destination)
        if (destination !== runtime.stdout) {
            destination.close()
        }
        SUCCESS_EXIT
    }

private suspend fun executeScope(
    scope: CliArgs.Scope,
    runtime: CliRuntime,
): List<OperatorDecryptOutput.DecryptedRow> =
    when (scope) {
        is CliArgs.Scope.KeyHandle -> {
            // Try DEK first; fall back to JWT signing key lookup if no match.
            val dekRows = runtime.dekExecutor.execute(scope.handleHex)
            dekRows.ifEmpty { runtime.jwtExecutor.execute(scope.handleHex) }
        }
        is CliArgs.Scope.AuditEventId -> runtime.auditDetailExecutor.execute(scope.id)
        is CliArgs.Scope.Ids -> emptyList() // v1.0: scope reserved for future per-table executors
        is CliArgs.Scope.TimeWindow -> emptyList() // v1.0: scope reserved for future per-table executors
    }

private fun parseSpanHours(args: CliArgs): Long? {
    val since = args.sinceIso ?: return null
    val until = args.untilIso ?: return null
    val sinceInst = kotlinx.datetime.Instant.parse(since)
    val untilInst = kotlinx.datetime.Instant.parse(until)
    val deltaMs = (untilInst.toEpochMilliseconds() - sinceInst.toEpochMilliseconds()).coerceAtLeast(0)
    return deltaMs / MILLIS_PER_HOUR
}

private fun tablesFor(args: CliArgs): List<String> {
    if (args.tables.isNotEmpty()) return args.tables
    return when (args.scope) {
        is CliArgs.Scope.KeyHandle -> listOf("security_keys.deks", "security_keys.jwt_signing_keys")
        is CliArgs.Scope.AuditEventId -> listOf("security_keys.audit_events")
        is CliArgs.Scope.Ids -> emptyList()
        is CliArgs.Scope.TimeWindow -> emptyList()
    }
}

private const val SUCCESS_EXIT = 0
private const val USAGE_EXIT = 64
private const val HARD_CAP_EXIT = 65
private const val SOFTWARE_EXIT = 70
private const val MILLIS_PER_HOUR = 3_600_000L

/**
 * Runtime DI bundle. `bootProduction()` opens a JDBC pool against the
 * security-service MySQL using the same env-var conventions as the running
 * service (`SECURITY_DB_*` + `AUDIT_HMAC_KEY`), so an operator who has access
 * to the security-service prod env file can launch the CLI without further
 * config. Tests pass a hand-rolled instance instead.
 */
data class CliRuntime(
    val auditLog: AuditLogPort,
    val auditLogQuery: AuditLogQueryPort,
    val dekRepository: DekRepository,
    val jwtRepository: JwtSigningKeyRepository,
    val stdout: java.io.PrintStream = System.out,
    val stderr: java.io.PrintStream = System.err,
) {
    val audit: OperatorDecryptAudit = OperatorDecryptAudit(auditLog)
    val dekExecutor: UnwrapDekExecutor = UnwrapDekExecutor(dekRepository)
    val jwtExecutor: JwtSigningKeyExecutor = JwtSigningKeyExecutor(jwtRepository)
    val auditDetailExecutor: AuditDetailExecutor = AuditDetailExecutor(auditLogQuery)
    val output: OperatorDecryptOutput = OperatorDecryptOutput(stdout, stderr)

    companion object {
        fun bootProduction(): CliRuntime = ProductionCliRuntime.boot()
    }
}

private val HELP_TEXT =
    """
    decrypt-cli — operator decrypt CLI (Phase 14 Stream M)

    Scope (single-sided per feedback_operator_decrypt_cli_single_sided.md):
      security-service-owned ciphertext only. The monolith does NOT host a
      sibling CLI.

    Argument surface (locked at SKS-M03 sign-off — see ParityArg.kt):
      --since <iso8601>            time-window scope start
      --until <iso8601>            time-window scope end
      --table <name> [...]         scope tables
      --ids <pk,pk,...>            explicit primary keys
      --key-handle <hex>           decrypt all rows bound to one DEK / JWT kid
      --audit-event-id <id>        decrypt one audit event's detail_json
      --output {json|jsonl|csv}    default json
      --output-file <path>         requires --i-accept-plaintext-on-disk
      --dry-run                    show what would be decrypted, no plaintext
      --operator-email <addr>      REQUIRED — RFC 5322 email
      --reason <string>            REQUIRED — 16–256 chars
      --correlation-id <uuid>      optional
      --i-understand-large-export  overrides the 10 000-row / 24 h hard cap
      --i-accept-plaintext-on-disk required if --output-file is set

    Audit (CLAUDE.md rule 26): each invocation emits exactly one
      OPERATOR_DECRYPT_RUN row to security_keys.audit_events BEFORE any
      unwrap. Plaintext is never logged or persisted by default.

    Exit codes:
      0   success
      64  usage error
      65  hard cap exceeded
      70  software error

    Runbook (M.2): security-service/docs/OPERATOR_DECRYPT_RUNBOOK.md.
    """.trimIndent()
