package com.shared.security.tools.decryptcli

/**
 * Phase 14 Stream M (SKS-M10/M14) — parsed argument bundle for the operator decrypt
 * CLI. Built from argv by [parseCliArgs]; instances are immutable. Per
 * `feedback_operator_decrypt_cli_single_sided.md` the parser is single-sided —
 * no shared lib with a monolith sibling.
 *
 * Invariants enforced by the parser:
 *
 *   1. `--operator-email` and `--reason` are required.
 *   2. At least ONE scope flag ([Since]/[Until], [Ids], [KeyHandle], or [AuditEventId])
 *      must be present.
 *   3. `--output-file` requires the matching `--i-accept-plaintext-on-disk` flag
 *      (CLAUDE.md rule 27).
 *   4. `--reason` length must be in [16..256] chars.
 *   5. `--operator-email` must look like an RFC 5322 email.
 *   6. Unknown flags fail parsing with an explicit error.
 *
 * Validation happens at parse time so the CLI fails BEFORE the audit row is
 * written (per the proposal §5.1 — the audit row is written only after
 * argument validation completes).
 */
data class CliArgs(
    val sinceIso: String?,
    val untilIso: String?,
    val tables: List<String>,
    val ids: List<String>,
    val keyHandle: String?,
    val auditEventId: Long?,
    val output: OutputFormat,
    val outputFile: String?,
    val dryRun: Boolean,
    val operatorEmail: String,
    val reason: String,
    val correlationId: String?,
    val iUnderstandLargeExport: Boolean,
    val iAcceptPlaintextOnDisk: Boolean,
) {
    enum class OutputFormat { JSON, JSONL, CSV }

    val outputDestination: String
        get() = if (outputFile != null) "file" else "stdout"

    val scope: Scope by lazy {
        when {
            keyHandle != null -> Scope.KeyHandle(keyHandle)
            auditEventId != null -> Scope.AuditEventId(auditEventId)
            ids.isNotEmpty() -> Scope.Ids(ids)
            sinceIso != null || untilIso != null -> Scope.TimeWindow(sinceIso, untilIso)
            else -> error("CliArgs invariant violation: scope missing — parser should have rejected this")
        }
    }

    sealed class Scope {
        data class KeyHandle(val handleHex: String) : Scope()

        data class AuditEventId(val id: Long) : Scope()

        data class Ids(val pks: List<String>) : Scope()

        data class TimeWindow(val sinceIso: String?, val untilIso: String?) : Scope()
    }
}

/** Exception raised by the parser; the CLI exits 64 (usage error) when this fires. */
class CliArgsParseException(message: String) : RuntimeException(message)

private const val REASON_MIN = 16
private const val REASON_MAX = 256

@Suppress("CyclomaticComplexMethod", "LongMethod", "NestedBlockDepth", "ThrowsCount")
fun parseCliArgs(argv: Array<String>): CliArgs {
    val recognised = ParityArg.all.associateBy { it.flagName }
    val booleanFlagNames = ParityArg.booleanFlags.map { it.flagName }.toSet()
    val repeatableFlagNames = ParityArg.repeatableFlags.map { it.flagName }.toSet()

    var since: String? = null
    var until: String? = null
    val tables = mutableListOf<String>()
    val ids = mutableListOf<String>()
    var keyHandle: String? = null
    var auditEventId: Long? = null
    var output: CliArgs.OutputFormat = CliArgs.OutputFormat.JSON
    var outputFile: String? = null
    var dryRun = false
    var operatorEmail: String? = null
    var reason: String? = null
    var correlationId: String? = null
    var iUnderstandLargeExport = false
    var iAcceptPlaintextOnDisk = false

    var i = 0
    while (i < argv.size) {
        val flag = argv[i]
        val arg =
            recognised[flag]
                ?: throw CliArgsParseException("Unknown flag: $flag. Run with --help for the catalog.")
        if (flag in booleanFlagNames) {
            when (arg) {
                ParityArg.DryRun -> dryRun = true
                ParityArg.IUnderstandLargeExport -> iUnderstandLargeExport = true
                ParityArg.IAcceptPlaintextOnDisk -> iAcceptPlaintextOnDisk = true
                else -> error("boolean flag $flag missing dispatch")
            }
            i++
            continue
        }
        if (i + 1 >= argv.size) {
            throw CliArgsParseException("$flag requires a value")
        }
        val value = argv[i + 1]
        when (arg) {
            ParityArg.Since -> since = value
            ParityArg.Until -> until = value
            ParityArg.Table -> tables.add(value)
            ParityArg.Ids -> ids.addAll(value.split(',').map { it.trim() }.filter { it.isNotEmpty() })
            ParityArg.KeyHandle -> keyHandle = value
            ParityArg.AuditEventId ->
                auditEventId =
                    value.toLongOrNull()
                        ?: throw CliArgsParseException("--audit-event-id must be a long, got: $value")
            ParityArg.Output ->
                output =
                    when (value.lowercase()) {
                        "json" -> CliArgs.OutputFormat.JSON
                        "jsonl" -> CliArgs.OutputFormat.JSONL
                        "csv" -> CliArgs.OutputFormat.CSV
                        else -> throw CliArgsParseException("--output must be one of json|jsonl|csv, got: $value")
                    }
            ParityArg.OutputFile -> outputFile = value
            ParityArg.OperatorEmail -> operatorEmail = value
            ParityArg.Reason -> reason = value
            ParityArg.CorrelationId -> correlationId = value
            else -> error("non-boolean flag $flag missing dispatch")
        }
        if (flag !in repeatableFlagNames && flag !in setOf(ParityArg.Ids.flagName)) {
            // Re-specification of a non-repeatable flag silently overwrites; allowed by spec.
        }
        i += 2
    }

    val email =
        operatorEmail
            ?: throw CliArgsParseException("--operator-email is required")
    if (!email.contains('@') || email.length > MAX_EMAIL_LENGTH) {
        throw CliArgsParseException("--operator-email is not a valid RFC 5322 email")
    }
    val reasonValue =
        reason
            ?: throw CliArgsParseException("--reason is required")
    if (reasonValue.length !in REASON_MIN..REASON_MAX) {
        throw CliArgsParseException(
            "--reason length must be $REASON_MIN..$REASON_MAX chars, got ${reasonValue.length}",
        )
    }
    val hasScope =
        keyHandle != null || auditEventId != null || ids.isNotEmpty() ||
            since != null || until != null
    if (!hasScope) {
        throw CliArgsParseException(
            "At least one scope flag is required: --since/--until, --ids, --key-handle, --audit-event-id",
        )
    }
    if (outputFile != null && !iAcceptPlaintextOnDisk) {
        throw CliArgsParseException(
            "--output-file requires --i-accept-plaintext-on-disk (CLAUDE.md rule 27 — plaintext on disk is opt-in)",
        )
    }
    return CliArgs(
        sinceIso = since,
        untilIso = until,
        tables = tables.toList(),
        ids = ids.toList(),
        keyHandle = keyHandle,
        auditEventId = auditEventId,
        output = output,
        outputFile = outputFile,
        dryRun = dryRun,
        operatorEmail = email,
        reason = reasonValue,
        correlationId = correlationId,
        iUnderstandLargeExport = iUnderstandLargeExport,
        iAcceptPlaintextOnDisk = iAcceptPlaintextOnDisk,
    )
}

private const val MAX_EMAIL_LENGTH = 254
