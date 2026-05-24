package com.shared.security.tools.decryptcli

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 14 Stream M (SKS-M07) — schema-validity test for the operator decrypt CLI
 * output envelope.
 *
 * The original M.0 plan called for a cross-repo SHA-256 parity check between a
 * monolith copy of the schema and a security-service copy. Per
 * `feedback_operator_decrypt_cli_single_sided.md` the monolith does not host a
 * sibling CLI, so the SHA-256 parity test is replaced with this single-side
 * schema-integrity test:
 *
 *   1. The schema file loads as valid JSON.
 *   2. The top-level required fields enumerated in M.0 are present.
 *   3. The locked schema_version constant is `"1.0"` (any future bump must
 *      explicitly update this test, forcing reviewer attention).
 *   4. The `invocation.side` enum is locked to `"security-service"` (no monolith
 *      side any more).
 *   5. The `column_decrypts` value type is `string` (binary outputs MUST be
 *      base64-encoded by the CLI; the schema enforces no leaks of raw bytes).
 *   6. The `Invocation` required field set matches the M.0 ticket spec exactly.
 *
 * Schema-version bumps require a follow-up ticket and updating this test in the
 * same PR.
 */
class OperatorDecryptOutputSchemaTest {
    private val json =
        Json {
            ignoreUnknownKeys = false
            isLenient = false
        }

    private fun loadSchema(): JsonObject {
        val stream =
            this::class.java.classLoader.getResourceAsStream("operator_decrypt_output.schema.json")
                ?: error("operator_decrypt_output.schema.json missing from classpath resources")
        return stream.use { json.parseToJsonElement(String(it.readBytes())).jsonObject }
    }

    @Test
    fun `schema document parses as valid JSON`() {
        val schema = loadSchema()
        assertNotNull(schema)
        assertEquals("https://json-schema.org/draft/2020-12/schema", schema["\$schema"]?.jsonPrimitive?.contentOrNull)
    }

    @Test
    fun `top-level required fields enumerate the M-0 locked set`() {
        val required =
            loadSchema()["required"]?.jsonArray
                ?.mapNotNull { it.jsonPrimitive.contentOrNull }
                ?.toSet()
                .orEmpty()
        val expected =
            setOf("schema_version", "invocation", "row_count", "rows", "warnings")
        assertEquals(expected, required, "top-level required field set drifted from the M.0 lock")
    }

    @Test
    fun `schema_version const is locked to 1-0`() {
        val versionConst =
            loadSchema()["properties"]?.jsonObject
                ?.get("schema_version")?.jsonObject
                ?.get("const")?.jsonPrimitive?.contentOrNull
        assertEquals("1.0", versionConst, "schema_version bump must update this test in the same PR")
    }

    @Test
    fun `invocation side constant is locked to security-service`() {
        val sideConst =
            loadSchema()["\$defs"]?.jsonObject
                ?.get("Invocation")?.jsonObject
                ?.get("properties")?.jsonObject
                ?.get("side")?.jsonObject
                ?.get("const")?.jsonPrimitive?.contentOrNull
        assertEquals(
            "security-service",
            sideConst,
            "Stream M is single-sided per feedback_operator_decrypt_cli_single_sided.md — " +
                "invocation.side must be locked to security-service",
        )
    }

    @Test
    fun `column_decrypts values are string-typed to forbid raw-byte leaks`() {
        val itemsType =
            loadSchema()["\$defs"]?.jsonObject
                ?.get("DecryptedRow")?.jsonObject
                ?.get("properties")?.jsonObject
                ?.get("column_decrypts")?.jsonObject
                ?.get("additionalProperties")?.jsonObject
                ?.get("type")?.jsonPrimitive?.contentOrNull
        assertEquals(
            "string",
            itemsType,
            "column_decrypts values MUST be string — binary outputs are base64-encoded by the CLI before insertion",
        )
    }

    @Test
    fun `Invocation required field set matches the M-0 spec`() {
        val invocationRequired =
            loadSchema()["\$defs"]?.jsonObject
                ?.get("Invocation")?.jsonObject
                ?.get("required")?.jsonArray
                ?.mapNotNull { it.jsonPrimitive.contentOrNull }
                ?.toSet()
                .orEmpty()
        val expected =
            setOf(
                "operator_email", "reason", "argument_vector",
                "started_at", "finished_at", "side", "dry_run",
                "i_understand_large_export", "i_accept_plaintext_on_disk",
                "output_destination",
            )
        assertEquals(expected, invocationRequired, "Invocation required field set drifted from the M.0 lock")
    }

    @Test
    fun `additionalProperties is false on the top-level and on every nested object`() {
        val schema = loadSchema()
        assertEquals(
            false,
            schema["additionalProperties"]?.jsonPrimitive?.boolean,
            "top-level additionalProperties must be false — schema bumps must add fields explicitly",
        )
        // Walk all $defs subobjects and assert additionalProperties=false for each.
        val defs = schema["\$defs"]?.jsonObject ?: return
        defs.forEach { (name, def) ->
            val obj = def.jsonObject
            // Some $defs may be union-typed; we only enforce additionalProperties on object-typed defs.
            val typeField = obj["type"]?.jsonPrimitive?.contentOrNull
            if (typeField == "object") {
                val addProps = obj["additionalProperties"]?.jsonPrimitive?.boolean
                assertTrue(
                    addProps == false,
                    "\$defs.$name must set additionalProperties=false to forbid unrecognised keys",
                )
            }
        }
    }
}
