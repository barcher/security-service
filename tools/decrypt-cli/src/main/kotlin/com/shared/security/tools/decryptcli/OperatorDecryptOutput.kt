package com.shared.security.tools.decryptcli

import kotlinx.datetime.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.PrintStream

/**
 * Phase 14 Stream M (SKS-M10/M12) — renders the operator decrypt output document.
 *
 * The output schema is locked at `schema_version="1.0"` (see
 * `operator_decrypt_output.schema.json`). Single-sided per
 * `feedback_operator_decrypt_cli_single_sided.md`: `invocation.side` is always
 * `"security-service"`.
 *
 * Three output formats:
 *
 *   * **json** (default) — single top-level object with `invocation` envelope.
 *   * **jsonl** — one JSON line per row; the `invocation` envelope is emitted
 *     to stderr at run start so it stays out of the line stream.
 *   * **csv** — header row + one row per result. Column names from the union
 *     of decrypt columns seen.
 *
 * Plaintext destination is stdout by default; `--output-file` (paired with
 * `--i-accept-plaintext-on-disk`) writes to the named path.
 */
class OperatorDecryptOutput(
    private val stdout: PrintStream,
    private val stderr: PrintStream,
) {
    private val json = Json { prettyPrint = true }

    data class DecryptedRow(
        val table: String,
        val primaryKey: String,
        val dekHandleHex: String? = null,
        val keyHandle: String? = null,
        val columnDecrypts: Map<String, String> = emptyMap(),
    )

    data class Document(
        val invocation: Invocation,
        val rows: List<DecryptedRow>,
        val warnings: List<String> = emptyList(),
    )

    data class Invocation(
        val operatorEmail: String,
        val reason: String,
        val argumentVector: List<String>,
        val correlationId: String?,
        val startedAt: Instant,
        val finishedAt: Instant,
        val dryRun: Boolean,
        val iUnderstandLargeExport: Boolean,
        val iAcceptPlaintextOnDisk: Boolean,
        val outputDestination: String,
    )

    fun render(
        document: Document,
        format: CliArgs.OutputFormat,
        destination: PrintStream = stdout,
    ) {
        when (format) {
            CliArgs.OutputFormat.JSON -> renderJson(document, destination)
            CliArgs.OutputFormat.JSONL -> renderJsonl(document, destination)
            CliArgs.OutputFormat.CSV -> renderCsv(document, destination)
        }
    }

    private fun renderJson(
        document: Document,
        destination: PrintStream,
    ) {
        destination.println(json.encodeToString(JsonObject.serializer(), toJsonObject(document)))
    }

    private fun renderJsonl(
        document: Document,
        destination: PrintStream,
    ) {
        // Emit the invocation envelope to stderr so jsonl consumers don't have to filter it.
        stderr.println(json.encodeToString(JsonObject.serializer(), invocationJson(document.invocation)))
        for (row in document.rows) {
            destination.println(Json.encodeToString(JsonObject.serializer(), rowJson(row)))
        }
    }

    private fun renderCsv(
        document: Document,
        destination: PrintStream,
    ) {
        val columnSet = document.rows.flatMap { it.columnDecrypts.keys }.toSortedSet()
        val header = listOf("table", "primary_key", "dek_handle_hex", "key_handle") + columnSet.toList()
        destination.println(header.joinToString(",") { csvEscape(it) })
        for (row in document.rows) {
            val baseFields =
                listOf(row.table, row.primaryKey, row.dekHandleHex.orEmpty(), row.keyHandle.orEmpty())
            val columnValues = columnSet.map { row.columnDecrypts[it].orEmpty() }
            destination.println((baseFields + columnValues).joinToString(",") { csvEscape(it) })
        }
    }

    private fun toJsonObject(document: Document): JsonObject =
        buildJsonObject {
            put("schema_version", JsonPrimitive("1.0"))
            put("invocation", invocationJson(document.invocation))
            put("row_count", JsonPrimitive(document.rows.size))
            put("rows", buildJsonArray { document.rows.forEach { add(rowJson(it)) } })
            put(
                "warnings",
                buildJsonArray { document.warnings.forEach { add(JsonPrimitive(it)) } },
            )
        }

    private fun invocationJson(invocation: Invocation): JsonObject =
        buildJsonObject {
            put("operator_email", JsonPrimitive(invocation.operatorEmail))
            put("reason", JsonPrimitive(invocation.reason))
            put(
                "argument_vector",
                buildJsonArray { invocation.argumentVector.forEach { add(JsonPrimitive(it)) } },
            )
            put("correlation_id", invocation.correlationId?.let { JsonPrimitive(it) } ?: JsonPrimitive(null as String?))
            put("started_at", JsonPrimitive(invocation.startedAt.toString()))
            put("finished_at", JsonPrimitive(invocation.finishedAt.toString()))
            put("side", JsonPrimitive("security-service"))
            put("dry_run", JsonPrimitive(invocation.dryRun))
            put("i_understand_large_export", JsonPrimitive(invocation.iUnderstandLargeExport))
            put("i_accept_plaintext_on_disk", JsonPrimitive(invocation.iAcceptPlaintextOnDisk))
            put("output_destination", JsonPrimitive(invocation.outputDestination))
        }

    private fun rowJson(row: DecryptedRow): JsonObject =
        buildJsonObject {
            put("table", JsonPrimitive(row.table))
            put("primary_key", JsonPrimitive(row.primaryKey))
            put("dek_handle_hex", row.dekHandleHex?.let { JsonPrimitive(it) } ?: JsonPrimitive(null as String?))
            row.keyHandle?.let { put("key_handle", JsonPrimitive(it)) }
            put(
                "column_decrypts",
                buildJsonObject { row.columnDecrypts.forEach { (k, v) -> put(k, JsonPrimitive(v)) } },
            )
        }

    private fun csvEscape(value: String): String {
        val needsQuote = value.contains(',') || value.contains('"') || value.contains('\n')
        return if (needsQuote) "\"" + value.replace("\"", "\"\"") + "\"" else value
    }
}
