package com.shared.security.infrastructure

import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Phase 14 Stream M (SKS-M16) — ArchUnit ratchets for the operator decrypt CLI.
 *
 * Single-sided per `feedback_operator_decrypt_cli_single_sided.md`. Three rules
 * (S-17 / S-18 / S-19) — renumbered from the original ticket text's S-14/15/16
 * to avoid colliding with Stream L L.0's already-shipped S-14/15/16
 * observability rules.
 *
 *   * **S-17** — no `adapters/inbound/http/` route handler returns a DTO field
 *     named `plaintext` or `decryptedValue`. The security service exposes key
 *     material via `/v1/dek/unwrap` (which returns DEK bytes) and never
 *     returns table-row plaintext. Allow-list: explicitly the existing JSON
 *     DTOs that carry key bytes (`UnwrapDekResponse`, etc.).
 *   * **S-18** — no class under `tools/decrypt-cli/` is reachable from
 *     `Application.module()` / `routing { }` / any other Ktor entry. The CLI
 *     is a separate executable; routing the CLI through HTTP would defeat
 *     the entire audit-lane separation.
 *   * **S-19** — no SLF4J call inside the `tools/decrypt-cli/` module
 *     references a plaintext-bearing variable name (`plaintext`, `decrypted`,
 *     `clear`, `unwrapped`). Plaintext must not leave the CLI's `stdout` /
 *     `--output-file` paths. Strict from day one (no exemptions).
 */
class StreamMBoundaryArchTest {
    private val allClasses =
        ClassFileImporter()
            .withImportOption(ImportOption.DoNotIncludeTests())
            .importPackages("com.shared.security")

    @Test
    @Suppress("NestedBlockDepth") // file-walk + nested filter + per-pattern check is structural
    fun `S-17 no inbound HTTP route handler returns a DTO containing plaintext or decryptedValue field`() {
        val sourceRoot = locateRepoRoot().resolve("adapters/inbound/http/src/main")
        val bannedFieldNames = listOf("plaintext", "decryptedValue")
        val violations = collectS17Violations(sourceRoot, bannedFieldNames)
        check(violations.isEmpty()) {
            "S-17 violation — HTTP route DTOs MUST NOT expose table plaintext over the wire " +
                "(CLAUDE.md rule 24). Offenders: $violations"
        }
    }

    private fun collectS17Violations(
        sourceRoot: Path,
        bannedFieldNames: List<String>,
    ): List<String> {
        if (!Files.isDirectory(sourceRoot)) return emptyList()
        val violations = mutableListOf<String>()
        Files.walk(sourceRoot).use { stream ->
            stream
                .filter { Files.isRegularFile(it) }
                .filter { it.fileName.toString().endsWith(".kt") }
                .filter { !it.toString().contains("/build/") }
                .forEach { path -> scanForBannedFields(path, bannedFieldNames, violations) }
        }
        return violations
    }

    private fun scanForBannedFields(
        path: Path,
        bannedFieldNames: List<String>,
        violations: MutableList<String>,
    ) {
        val text = Files.readString(path)
        for (banned in bannedFieldNames) {
            if (Regex("\\bval\\s+$banned\\s*:").containsMatchIn(text)) {
                violations.add("${path.fileName} contains field `val $banned:`")
            }
        }
    }

    @Test
    fun `S-18 no class under tools-decrypt-cli is reachable from Application module or routing`() {
        // The CLI module is a separate executable. Its top-level `com.shared.security.tools.decryptcli`
        // package MUST NOT be referenced from any `com.shared.security.infrastructure` class that
        // builds the HTTP routing graph.
        noClasses()
            .that().resideInAPackage("com.shared.security.infrastructure..")
            .should().dependOnClassesThat()
            .resideInAPackage("com.shared.security.tools.decryptcli..")
            .allowEmptyShould(true)
            .check(allClasses)
    }

    @Test
    fun `S-19 no SLF4J call in tools-decrypt-cli references a plaintext-bearing variable name`() {
        val sourceRoot = locateRepoRoot().resolve("tools/decrypt-cli/src/main/kotlin")
        if (!Files.isDirectory(sourceRoot)) {
            check(false) { "tools/decrypt-cli source tree missing — expected $sourceRoot" }
        }
        val bannedNames = listOf("plaintext", "decrypted", "clear", "unwrapped")
        val violations = mutableListOf<String>()
        Files.walk(sourceRoot).use { stream ->
            stream
                .filter { Files.isRegularFile(it) }
                .filter { it.fileName.toString().endsWith(".kt") }
                .filter { !it.toString().contains("/build/") }
                .forEach { path ->
                    val text = Files.readString(path)
                    // Match SLF4J logger calls — look for `.info(` / `.warn(` / `.debug(` /
                    // `.trace(` followed within the same call by a banned identifier substring.
                    val joined = bannedNames.joinToString("|")
                    val loggerCall = Regex("\\.(info|warn|debug|trace)\\([^)]*?\\b($joined)\\b")
                    if (loggerCall.containsMatchIn(text)) {
                        violations.add("${path.fileName} logs a plaintext-bearing identifier")
                    }
                }
        }
        check(violations.isEmpty()) {
            "S-19 violation — SLF4J calls in tools/decrypt-cli/ MUST NOT include plaintext-bearing " +
                "identifiers (CLAUDE.md rule 27). Offenders: $violations"
        }
    }

    private fun locateRepoRoot(): Path {
        // Tests run from infrastructure/, repo root is the parent.
        val candidates =
            listOf(
                Paths.get("..").toAbsolutePath().normalize(),
                Paths.get(".").toAbsolutePath().normalize(),
            )
        return candidates.first { Files.isDirectory(it.resolve("tools/decrypt-cli")) }
    }
}
