package com.shared.security.infrastructure

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * S-9: `CryptoKeyServicePort.kt` in this repo must be byte-identical to the monolith's
 * copy at `scaffold/application/.../ports/CryptoKeyServicePort.kt`, modulo the package
 * declaration on line 1. Any other difference is a contract drift that breaks the
 * structural promise that "the wire shape and the in-process port shape are the same".
 *
 * The check loads the monolith's copy from a sibling repo at the conventional relative
 * path `../../scaffold/...`. When that path isn't present (e.g. running tests from a
 * standalone checkout that doesn't include `scaffold/`), the test is **skipped** rather
 * than failed — S-9 is enforced in CI environments that have both repos checked out;
 * developers running on just `security-service/` are not blocked.
 */
class CryptoKeyServicePortIdentityTest {
    @Test
    fun `S-9 CryptoKeyServicePort matches scaffold copy byte-for-byte modulo package line`() {
        val ourCopy = resolveOurCopy()
        val scaffoldCopy = resolveScaffoldCopy()
        assumeTrue(
            scaffoldCopy != null && Files.exists(scaffoldCopy),
            "Scaffold checkout not present at the conventional sibling path — S-9 enforcement skipped. " +
                "In CI, both repos are checked out side-by-side and the test runs.",
        )

        val ourLines = Files.readAllLines(ourCopy).withoutPackageLine()
        val scaffoldLines = Files.readAllLines(scaffoldCopy!!).withoutPackageLine()

        assertEquals(
            scaffoldLines,
            ourLines,
            "CryptoKeyServicePort.kt has drifted between security-service and scaffold. " +
                "The two files MUST be byte-identical except for line 1 (package). Re-sync from " +
                "whichever side is authoritative for this change (typically: design changes start in " +
                "the security service and propagate to the monolith via this port).",
        )
    }

    private fun List<String>.withoutPackageLine(): List<String> {
        val hasPackageHeader = isNotEmpty() && first().startsWith("package ")
        return if (hasPackageHeader) drop(1) else this
    }

    private fun resolveOurCopy(): Path {
        val candidates =
            listOf(
                Paths.get(
                    "..",
                    "application",
                    "src",
                    "main",
                    "kotlin",
                    "com",
                    "shared",
                    "security",
                    "application",
                    "ports",
                    "CryptoKeyServicePort.kt",
                ),
                Paths.get(
                    "application",
                    "src",
                    "main",
                    "kotlin",
                    "com",
                    "shared",
                    "security",
                    "application",
                    "ports",
                    "CryptoKeyServicePort.kt",
                ),
            )
        return candidates.firstOrNull { Files.exists(it) }
            ?: error("Could not locate this repo's CryptoKeyServicePort.kt from ${Paths.get("").toAbsolutePath()}")
    }

    private fun resolveScaffoldCopy(): Path? {
        val candidates =
            listOf(
                Paths.get(
                    "..",
                    "..",
                    "scaffold",
                    "application",
                    "src",
                    "main",
                    "kotlin",
                    "com",
                    "workautomations",
                    "application",
                    "ports",
                    "CryptoKeyServicePort.kt",
                ),
                Paths.get(
                    "..",
                    "scaffold",
                    "application",
                    "src",
                    "main",
                    "kotlin",
                    "com",
                    "workautomations",
                    "application",
                    "ports",
                    "CryptoKeyServicePort.kt",
                ),
            )
        return candidates.firstOrNull { Files.exists(it) }
    }
}
