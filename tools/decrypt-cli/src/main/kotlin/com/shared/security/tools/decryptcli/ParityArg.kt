package com.shared.security.tools.decryptcli

/**
 * Phase 14 Stream M (SKS-M03) — canonical argument surface for `decrypt-cli`.
 *
 * Originally specified as a parity contract between a monolith CLI and a
 * security-service CLI (proposal §4). Per
 * `feedback_operator_decrypt_cli_single_sided.md` the monolith CLI was cut, so
 * the "parity" here is now intra-repo only — between the lib code that parses
 * argv and the JSON output's `invocation.argument_vector` field. The sealed
 * class is still the source of truth: every recognised flag is enumerated here;
 * unknown flags fail parsing.
 *
 * Argument changes after M.0 sign-off require a documented schema-version bump
 * in `operator_decrypt_output.schema.json`. New optional flags can be added
 * without a bump; required-flag changes or renames force a bump.
 */
sealed class ParityArg {
    abstract val flagName: String

    /** Time-window scope start (ISO-8601). */
    data object Since : ParityArg() {
        override val flagName = "--since"
    }

    /** Time-window scope end (ISO-8601). */
    data object Until : ParityArg() {
        override val flagName = "--until"
    }

    /** Repeatable: explicit table name in scope. */
    data object Table : ParityArg() {
        override val flagName = "--table"
    }

    /** Comma-separated primary-key list. */
    data object Ids : ParityArg() {
        override val flagName = "--ids"
    }

    /** Decrypt all rows bound to one DEK handle (hex). */
    data object KeyHandle : ParityArg() {
        override val flagName = "--key-handle"
    }

    /** Decrypt one audit event's detail_json by id. */
    data object AuditEventId : ParityArg() {
        override val flagName = "--audit-event-id"
    }

    /** Output encoding: json (default) | jsonl | csv. */
    data object Output : ParityArg() {
        override val flagName = "--output"
    }

    /** Destination file path. Requires [IAcceptPlaintextOnDisk]. */
    data object OutputFile : ParityArg() {
        override val flagName = "--output-file"
    }

    /** Dry-run: validate + audit + count rows, but emit no plaintext. */
    data object DryRun : ParityArg() {
        override val flagName = "--dry-run"
    }

    /** REQUIRED — RFC 5322 operator email. Recorded in audit + output envelope. */
    data object OperatorEmail : ParityArg() {
        override val flagName = "--operator-email"
    }

    /** REQUIRED — 16..256 char free-text reason. Recorded in audit + output envelope. */
    data object Reason : ParityArg() {
        override val flagName = "--reason"
    }

    /** Optional incident-response correlation id (UUID-shaped). */
    data object CorrelationId : ParityArg() {
        override val flagName = "--correlation-id"
    }

    /** Override the 10 000-row / 24 h hard cap. Opt-in recorded in audit. */
    data object IUnderstandLargeExport : ParityArg() {
        override val flagName = "--i-understand-large-export"
    }

    /** Required when [OutputFile] is set. Opt-in recorded in audit. */
    data object IAcceptPlaintextOnDisk : ParityArg() {
        override val flagName = "--i-accept-plaintext-on-disk"
    }

    companion object {
        /** Every recognised flag. Unknown args fail parsing. */
        val all: List<ParityArg> =
            listOf(
                Since, Until, Table, Ids, KeyHandle, AuditEventId,
                Output, OutputFile, DryRun,
                OperatorEmail, Reason, CorrelationId,
                IUnderstandLargeExport, IAcceptPlaintextOnDisk,
            )

        /** Flags an operator must supply on every invocation. */
        val required: Set<ParityArg> = setOf(OperatorEmail, Reason)

        /** Boolean flags (no value). */
        val booleanFlags: Set<ParityArg> = setOf(DryRun, IUnderstandLargeExport, IAcceptPlaintextOnDisk)

        /** Flags allowed to repeat (e.g. multiple --table). */
        val repeatableFlags: Set<ParityArg> = setOf(Table)

        /**
         * At least ONE of these must be specified — the CLI refuses to run without a
         * scope. Time-window OR explicit IDs OR key-handle OR audit-event-id.
         */
        val scopeFlags: Set<ParityArg> = setOf(Since, Until, Ids, KeyHandle, AuditEventId)
    }
}
