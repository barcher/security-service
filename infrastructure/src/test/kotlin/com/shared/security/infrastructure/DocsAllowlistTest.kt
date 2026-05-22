package com.shared.security.infrastructure

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * S-7 enforcer: every `.md` file under `security-service/docs/` matches the canonical
 * allowlist below (and every allowlist entry corresponds to an existing file). Adding a
 * new doc requires updating both this set AND `docs/README.md`'s table in the same
 * commit. Removing a doc requires removing the entry from both places.
 *
 * **Why a Kotlin set rather than parsing `docs/README.md`:** markdown parsing in a unit
 * test is fragile (escaping, formatting edge cases). The Kotlin set is the canonical
 * source of truth; the README is the human-readable mirror. The S-7 rule mandates the
 * two be kept in sync — the test catches drift the moment it lands.
 *
 * This test runs from the `infrastructure` module's working directory at test time
 * (`security-service/infrastructure/`), so `docs/` is resolved relative to that as
 * `../docs/`.
 */
class DocsAllowlistTest {
    @Test
    fun `S-7 every md file under docs is in the allowlist`() {
        val docsDir = resolveDocsDir()
        val onDisk =
            Files.list(docsDir).use { stream ->
                stream
                    .filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".md") }
                    .map { it.fileName.toString() }
                    .sorted()
                    .toList()
                    .toSet()
            }

        val unexpected = onDisk - ALLOWED_DOC_FILES
        assertTrue(
            unexpected.isEmpty(),
            "Unexpected .md files in docs/ (not in S-7 allowlist): $unexpected. " +
                "Add to ALLOWED_DOC_FILES + docs/README.md, or delete the file.",
        )
    }

    @Test
    fun `S-7 every allowlist entry corresponds to a file on disk`() {
        val docsDir = resolveDocsDir()
        val missing =
            ALLOWED_DOC_FILES.filter { !Files.exists(docsDir.resolve(it)) }
        assertTrue(
            missing.isEmpty(),
            "Allowlist entries with no file on disk: $missing. Either write the file or " +
                "remove from ALLOWED_DOC_FILES + docs/README.md.",
        )
    }

    @Test
    fun `S-7 docs subdirectories are not permitted`() {
        val docsDir = resolveDocsDir()
        val subdirs =
            Files.list(docsDir).use { stream ->
                stream
                    .filter { Files.isDirectory(it) }
                    .map { it.fileName.toString() }
                    .toList()
            }
        assertEquals(
            emptyList<String>(),
            subdirs,
            "Subdirectories are not permitted under docs/ — keep the layout flat per docs/README.md.",
        )
    }

    private fun resolveDocsDir(): Path {
        val candidates =
            listOf(
                Paths.get("..", "docs"),
                Paths.get("docs"),
                Paths.get("..", "..", "docs"),
            )
        return candidates.firstOrNull { Files.isDirectory(it) }
            ?: error("Could not locate security-service docs/ from working dir ${Paths.get("").toAbsolutePath()}")
    }

    companion object {
        /**
         * The canonical S-7 allowlist. Keep in sync with `docs/README.md` — the test in
         * `_S-7 every allowlist entry corresponds to a file on disk_` catches drift on the
         * filesystem side; reviewers catch drift on the README side at PR time.
         */
        private val ALLOWED_DOC_FILES =
            setOf(
                "README.md",
                "MTLS.md",
                "RATE_LIMITING.md",
                "AUDIT_LOG.md",
                "KEK_LIFECYCLE.md",
                "MIGRATIONS.md",
                "SECURITY_SCORECARD.md",
                "DEPLOYMENT.md",
                "CERT_GENERATION.md",
                "TRUST_MODEL.md",
                "HSM_KEY_CEREMONY.md",
            )
    }
}
