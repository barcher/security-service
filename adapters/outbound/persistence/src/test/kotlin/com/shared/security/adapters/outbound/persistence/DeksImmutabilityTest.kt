package com.shared.security.adapters.outbound.persistence

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Structural guard: the security service must NEVER delete rows from the `deks` table.
 *
 * A DEK row is the only record of how to unwrap the data encrypted under it. Deleting
 * the row destroys the data — a class of incident already seen in the monolith
 * (orphaned `enc:v0:<keyId>:…` ciphertext after a past rotation purged keys that were
 * still referenced). The monolith now gates its `deleteRetired` on a reference-count
 * scan; the security service mirrors that invariant by simply not exposing any delete
 * path on `deks` at all.
 *
 * This test scans every production Kotlin source file in
 * `adapters/outbound/persistence/src/main/kotlin/` and `application/src/main/kotlin/`
 * for patterns that would mutate the `deks` table by removal:
 *
 *   - `DeksTable.deleteWhere`
 *   - `DELETE FROM deks` (raw SQL)
 *   - `dropTable(.*Deks*` (table drop)
 *
 * If any match is found the test fails with the offending location. To add a legitimate
 * deletion path you MUST first add reference-counting (count callers across every
 * service that may hold wrapped DEKs) AND surface the design in a proposal — the test
 * exists to force that conversation.
 */
class DeksImmutabilityTest {
    @Test
    fun `no production code may delete from the deks table`() {
        val scanRoots = productionSourceRoots()
        assertTrue(scanRoots.isNotEmpty(), "no production source roots found — test path setup is wrong")
        val violations = scanRoots.flatMap { scanForViolations(it) }
        if (violations.isNotEmpty()) {
            val message =
                "DEK rows must never be deleted by the security service " +
                    "(reference-counted purge invariant). Violations:\n" +
                    violations.joinToString("\n") { "  - $it" } +
                    "\nIf you genuinely need a deletion path, add reference-counting first " +
                    "(see monolith's DekWrappedStringEncryptor.findReferencedKeyIds + " +
                    "EncryptionKeyRepository.deleteRetiredExcept for the pattern)."
            fail<Unit>(message)
        }
    }

    private fun productionSourceRoots(): List<File> =
        listOf(
            File("../../adapters/outbound/persistence/src/main/kotlin"),
            File("../../application/src/main/kotlin"),
            File("../../infrastructure/src/main/kotlin"),
            File("src/main/kotlin"),
        ).filter { it.exists() }

    private fun scanForViolations(root: File): List<String> =
        root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .flatMap { file -> matchesIn(file) }
            .toList()

    private fun matchesIn(file: File): List<String> {
        val contents = file.readText()
        return FORBIDDEN_PATTERNS.flatMap { pattern ->
            pattern.findAll(contents).map { "${file.path}: ${it.value}" }
        }
    }

    companion object {
        private val FORBIDDEN_PATTERNS =
            listOf(
                Regex("""DeksTable\s*\.\s*deleteWhere"""),
                Regex("""DELETE\s+FROM\s+deks\b""", RegexOption.IGNORE_CASE),
                Regex("""dropTable\s*\(\s*DeksTable""", RegexOption.IGNORE_CASE),
            )
    }
}
