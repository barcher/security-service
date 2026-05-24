package com.shared.security.tools.decryptcli

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 14 Stream M (SKS-M10) — argument-parsing unit tests.
 *
 * The parser must enforce its invariants BEFORE the audit row is written; the
 * test surface here is therefore the only safety net against bad-args
 * regressions.
 */
class CliArgsParseTest {
    private val ok =
        arrayOf(
            "--operator-email",
            "ops-alice@example.com",
            "--reason",
            "incident IR-2026-05-24-001 row inspection lookup",
            "--key-handle",
            "ab12cd34",
        )

    @Test
    fun `accepts minimal valid invocation`() {
        val parsed = parseCliArgs(ok)
        assertEquals("ops-alice@example.com", parsed.operatorEmail)
        assertEquals("ab12cd34", parsed.keyHandle)
        assertFalse(parsed.dryRun)
        assertEquals(CliArgs.OutputFormat.JSON, parsed.output)
    }

    @Test
    fun `rejects missing operator email`() {
        val argv =
            arrayOf(
                "--reason",
                "incident IR-2026-05-24-001 lookup test",
                "--key-handle",
                "ab12",
            )
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("operator-email"))
    }

    @Test
    fun `rejects missing reason`() {
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--key-handle",
                "ab12",
            )
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("reason"))
    }

    @Test
    fun `rejects reason shorter than 16 chars`() {
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "too short",
                "--key-handle",
                "ab12",
            )
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("reason"))
    }

    @Test
    fun `rejects unknown flag`() {
        val argv = ok + arrayOf("--unknown-flag", "x")
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("Unknown flag"))
    }

    @Test
    fun `rejects missing scope`() {
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 lookup test",
            )
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("scope"))
    }

    @Test
    fun `rejects output file without i-accept-plaintext-on-disk`() {
        val argv = ok + arrayOf("--output-file", "/tmp/decrypt.json")
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("i-accept-plaintext-on-disk"))
    }

    @Test
    fun `accepts output file when paired with i-accept-plaintext-on-disk`() {
        val argv =
            ok +
                arrayOf(
                    "--output-file", "/tmp/decrypt.json",
                    "--i-accept-plaintext-on-disk",
                )
        val parsed = parseCliArgs(argv)
        assertEquals("/tmp/decrypt.json", parsed.outputFile)
        assertTrue(parsed.iAcceptPlaintextOnDisk)
        assertEquals("file", parsed.outputDestination)
    }

    @Test
    fun `parses comma-separated ids into list`() {
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 lookup test",
                "--ids",
                "pk-1,pk-2, pk-3,, pk-4",
            )
        val parsed = parseCliArgs(argv)
        assertEquals(listOf("pk-1", "pk-2", "pk-3", "pk-4"), parsed.ids)
    }

    @Test
    fun `parses repeatable table flag`() {
        val argv =
            arrayOf(
                "--operator-email", "ops-alice@example.com",
                "--reason", "incident IR-2026-05-24-001 lookup test",
                "--table", "security_keys.deks",
                "--table", "security_keys.jwt_signing_keys",
                "--key-handle", "ab12",
            )
        val parsed = parseCliArgs(argv)
        assertEquals(listOf("security_keys.deks", "security_keys.jwt_signing_keys"), parsed.tables)
    }

    @Test
    fun `rejects unknown output format`() {
        val argv = ok + arrayOf("--output", "yaml")
        val thrown = assertThrows(CliArgsParseException::class.java) { parseCliArgs(argv) }
        assertTrue(thrown.message!!.contains("json|jsonl|csv"))
    }

    @Test
    fun `accepts time-window scope`() {
        val argv =
            arrayOf(
                "--operator-email",
                "ops-alice@example.com",
                "--reason",
                "incident IR-2026-05-24-001 lookup test",
                "--since",
                "2026-05-24T00:00:00Z",
                "--until",
                "2026-05-24T01:00:00Z",
            )
        val parsed = parseCliArgs(argv)
        assertEquals("2026-05-24T00:00:00Z", parsed.sinceIso)
        assertEquals("2026-05-24T01:00:00Z", parsed.untilIso)
    }

    @Test
    fun `parses dry run flag`() {
        val parsed = parseCliArgs(ok + "--dry-run")
        assertTrue(parsed.dryRun)
    }
}
