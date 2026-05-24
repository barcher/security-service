package com.shared.security.tools.decryptcli

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import kotlinx.datetime.Instant
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Phase 14 Stream M (SKS-M11/M12) — writes the per-invocation OPERATOR_DECRYPT_RUN
 * audit row.
 *
 * Per CLAUDE.md rule 26 the row is written BEFORE any unwrap call begins. The
 * row is the record that the operator started the decrypt — even if the run
 * later fails partway, the audit chain shows the attempt.
 *
 * `detail_json` schema (per CLAUDE.md rule 26):
 *
 * ```json
 * {
 *   "operator_email": "ops-alice@example.com",
 *   "reason": "incident IR-2026-05-17-001 row inspection",
 *   "argument_vector": ["--key-handle", "ab12...", "--operator-email", "ops-alice@example.com", ...],
 *   "correlation_id": "9c7d1e1a-...",
 *   "row_count": 2,
 *   "tables": ["security_keys.deks"],
 *   "output_destination": "stdout",
 *   "i_understand_large_export": false,
 *   "i_accept_plaintext_on_disk": false,
 *   "schema_version": "1.0"
 * }
 * ```
 *
 * The detail_json NEVER contains plaintext or decrypted bytes — only the
 * operator-stated reason, the argument vector (flag names + table/ID
 * references), and counts.
 */
class OperatorDecryptAudit(private val auditLog: AuditLogPort) {
    suspend fun writePreRun(
        args: CliArgs,
        argv: Array<String>,
        startedAt: Instant,
        rowCountEstimate: Long,
        tables: List<String>,
    ) {
        val detail = buildDetailJson(args, argv, rowCountEstimate, tables)
        auditLog.write(
            AuditEvent(
                occurredAt = startedAt,
                eventType = AuditEventType.OPERATOR_DECRYPT_RUN,
                actorSubject = CertSubjectDnValidator.expectedSubjectDn(args.operatorEmail),
                dekHandle = null,
                kekId = null,
                success = true,
                detailJson = detail.toString(),
            ),
        )
    }

    private fun buildDetailJson(
        args: CliArgs,
        argv: Array<String>,
        rowCountEstimate: Long,
        tables: List<String>,
    ): JsonObject =
        buildJsonObject {
            put("operator_email", JsonPrimitive(args.operatorEmail))
            put("reason", JsonPrimitive(args.reason))
            put("argument_vector", argvJson(argv))
            put("correlation_id", JsonPrimitive(args.correlationId))
            put("row_count", JsonPrimitive(rowCountEstimate))
            put("tables", tablesJson(tables))
            put("output_destination", JsonPrimitive(args.outputDestination))
            put("i_understand_large_export", JsonPrimitive(args.iUnderstandLargeExport))
            put("i_accept_plaintext_on_disk", JsonPrimitive(args.iAcceptPlaintextOnDisk))
            put("schema_version", JsonPrimitive(SCHEMA_VERSION))
        }

    private fun argvJson(argv: Array<String>): JsonArray =
        buildJsonArray {
            for (a in argv) {
                add(JsonPrimitive(a))
            }
        }

    private fun tablesJson(tables: List<String>): JsonArray =
        buildJsonArray {
            for (t in tables) {
                add(JsonPrimitive(t))
            }
        }

    private companion object {
        private const val SCHEMA_VERSION = "1.0"
    }
}
