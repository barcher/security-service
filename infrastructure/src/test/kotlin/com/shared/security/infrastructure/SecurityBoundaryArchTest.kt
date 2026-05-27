package com.shared.security.infrastructure

import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import org.junit.jupiter.api.Test

/**
 * Architectural rules for the security service. Maps to proposal §6.2 S-4..S-8.
 *
 * S-1, S-2, S-3 are asserted in the crypto module's own
 * `adapters/outbound/crypto/.../CryptoBoundaryArchTest` because they need to scan only
 * the crypto module's classes.
 *
 * S-7 (docs allowlist) is asserted as a plain JUnit test in [DocsAllowlistTest] because
 * it inspects filesystem contents rather than class metadata.
 *
 * S-9 (cross-repo port byte-identity) is **retired** as of the Phase-2 collapse of the
 * shared-security-client adoption: the canonical base port now lives in the shared client
 * library at `workAutomations/shared-security-client/` and is consumed by every service.
 * There is no longer a second copy in the monolith to keep in sync. The base wire DTOs
 * (`WrappedDek`, etc.) are owned by the shared module and evolve additively per its rules.
 */
class SecurityBoundaryArchTest {
    private val classes =
        ClassFileImporter()
            .withImportOption(ImportOption.DoNotIncludeTests())
            .importPackages("com.shared.security")

    @Test
    fun `S-4 application module must not depend on any adapter module`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.application..")
            .should().dependOnClassesThat()
            .resideInAnyPackage(
                "com.shared.security.adapters.inbound..",
                "com.shared.security.adapters.outbound..",
                "com.shared.security.infrastructure..",
            )
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun `S-5 application module must not depend on Ktor or HTTP framework types`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.application..")
            .should().dependOnClassesThat()
            .resideInAnyPackage(
                "io.ktor..",
                "io.netty..",
                "org.eclipse.jetty..",
            )
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun `S-6 application module must not depend on Exposed or JDBC types`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.application..")
            .should().dependOnClassesThat()
            .resideInAnyPackage(
                "org.jetbrains.exposed..",
                "java.sql..",
                "javax.sql..",
                "com.zaxxer.hikari..",
            )
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun `S-8 MlKemService is referenced only inside the crypto adapter module`() {
        noClasses()
            .that().resideInAnyPackage(
                "com.shared.security.application..",
                "com.shared.security.domain..",
                "com.shared.security.adapters.inbound..",
                "com.shared.security.adapters.outbound.persistence..",
                "com.shared.security.infrastructure..",
            )
            .should().dependOnClassesThat().haveSimpleName("MlKemService")
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun `S-8a NoOpCryptoKeyService is referenced only by infrastructure DI wiring`() {
        // NoOpCryptoKeyService is the fail-closed default. Any other module reaching for
        // it directly would be smuggling around the port abstraction — block it.
        noClasses()
            .that().resideInAnyPackage(
                "com.shared.security.application..",
                "com.shared.security.domain..",
                "com.shared.security.adapters.inbound..",
                "com.shared.security.adapters.outbound.persistence..",
            )
            .should().dependOnClassesThat().haveSimpleName("NoOpCryptoKeyService")
            .allowEmptyShould(true)
            .check(classes)
    }

    // -- Stream K K.0: internal-port + adapter-module isolation rules --

    /**
     * **S-11 — JWT signing primitives live ONLY in `adapters/outbound/jwt-signing/`.**
     * The signing module is a deliberately separate Gradle submodule (proposal §3.4b
     * rule 10); no other module may import the concrete `Es256SigningService` or
     * `Es256JwtSigningKeyAdapter` classes. Use cases consume the `JwtSigningKeyPort`
     * abstraction defined in `application/`.
     */
    @Test
    fun `S-11 Es256SigningService is referenced only inside the jwt-signing adapter module`() {
        noClasses()
            .that().resideInAnyPackage(
                "com.shared.security.application..",
                "com.shared.security.domain..",
                "com.shared.security.adapters.inbound..",
                "com.shared.security.adapters.outbound.persistence..",
                "com.shared.security.adapters.outbound.crypto..",
            )
            .should().dependOnClassesThat()
            .haveFullyQualifiedName("com.shared.security.adapters.outbound.jwtsigning.Es256SigningService")
            .orShould().dependOnClassesThat()
            .haveFullyQualifiedName("com.shared.security.adapters.outbound.jwtsigning.Es256JwtSigningKeyAdapter")
            .allowEmptyShould(true)
            .check(classes)
    }

    /**
     * **S-12 — JWT use cases consume `KekEnvelopePort`, NOT `CryptoKeyServicePort`.**
     * The internal-port pattern (proposal §3.4b) isolates the jwt/ application package
     * from the wider crypto contract. Any future JWT code path that reaches `wrapDek` /
     * `unwrapDek` / `generateDek` directly defeats the isolation invariant and fails
     * the build here.
     */
    @Test
    fun `S-12 application jwt use cases must not import CryptoKeyServicePort`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.application.usecases.jwt..")
            .should().dependOnClassesThat()
            .haveFullyQualifiedName("com.shared.security.application.ports.CryptoKeyServicePort")
            .allowEmptyShould(true)
            .check(classes)
    }

    /**
     * **S-13 — `KekEnvelopePort` has exactly one implementation: `KekEnvelopeAdapter`.**
     * The narrow internal port is the only bridge between the crypto submodule and the
     * jwt-signing path. A second implementation would imply a parallel bridge that
     * could bypass the AAD-binding contract. The test inspects the class hierarchy and
     * fails on any unexpected implementer.
     */
    @Test
    fun `S-13 KekEnvelopePort has exactly one implementer KekEnvelopeAdapter`() {
        val implementers =
            classes.filter { clazz ->
                clazz.interfaces.any { it.name == "com.shared.security.application.ports.KekEnvelopePort" }
            }.map { it.name }
        check(implementers == listOf("com.shared.security.adapters.outbound.crypto.KekEnvelopeAdapter")) {
            "KekEnvelopePort must be implemented only by KekEnvelopeAdapter, got: $implementers"
        }
    }

    // -- Stream L L.0: observability surface isolation rules --

    /**
     * **S-14 — `ObservabilityRoutes.kt` never references the crypto primitives.** The
     * observability surface is metadata-only. ArchUnit catches direct type references to
     * `CryptoKeyServicePort`, `KekEnvelopePort`, `JwtSigningKeyPort` from
     * `ObservabilityRoutes` or any of the observation use cases. A companion source-grep
     * test catches the four operation literals ("unwrap" / "wrap" / "generate" / "rewrap")
     * in case a future reviewer accidentally pastes a call into the file.
     */
    @Test
    fun `S-14 observation surface never depends on crypto primitive ports`() {
        val bannedPorts =
            setOf(
                "com.shared.security.application.ports.CryptoKeyServicePort",
                "com.shared.security.application.ports.KekEnvelopePort",
                "com.shared.security.application.usecases.jwt.JwtSigningKeyPort",
            )
        val offenders =
            classes.filter { clazz ->
                clazz.name.startsWith("com.shared.security.application.usecases.observation.") ||
                    clazz.name == "com.shared.security.adapters.inbound.http.ObservabilityRoutesKt"
            }.flatMap { clazz ->
                clazz.directDependenciesFromSelf
                    .filter { it.targetClass.name in bannedPorts }
                    .map { "${clazz.name} → ${it.targetClass.name}" }
            }
        check(offenders.isEmpty()) {
            "S-14 violation — observation surface references crypto primitives: $offenders"
        }
    }

    /**
     * **S-15 — `ObservabilityRoutes` mounts only `/v1/observability/`-prefixed routes.**
     * ArchUnit can't introspect the Ktor route tree at type level; we approximate by
     * grepping the source file for any `route("/v1/...")` or `get("/v1/...")` literal
     * that's not under `/v1/observability/`.
     */
    @Test
    fun `S-15 ObservabilityRoutes mounts only under v1 observability`() {
        val sourceFile =
            java.nio.file.Paths.get(
                "..",
                "adapters",
                "inbound",
                "http",
                "src",
                "main",
                "kotlin",
                "com",
                "shared",
                "security",
                "adapters",
                "inbound",
                "http",
                "ObservabilityRoutes.kt",
            )
        check(java.nio.file.Files.exists(sourceFile)) {
            "S-15 cannot find ObservabilityRoutes.kt at $sourceFile (test must run from infrastructure/)"
        }
        val text = java.nio.file.Files.readString(sourceFile)
        val pathLiterals = Regex("\"/v1/[^\"]*\"").findAll(text).map { it.value }.toList()
        val offending = pathLiterals.filter { !it.startsWith("\"/v1/observability") }
        check(offending.isEmpty()) {
            "S-15 violation — ObservabilityRoutes contains paths outside /v1/observability: $offending"
        }
    }

    /**
     * **S-16 — `DashboardObserverAllowList` is referenced only from `ObservabilityRoutes`
     * and the DI module.** No other route handler or use case may consult the observer
     * allow-list — that would mean a non-observability surface is using observer auth,
     * which collapses the four-lane subject-DN model.
     */
    @Test
    fun `S-16 DashboardObserverAllowList referenced only from ObservabilityRoutes and DI`() {
        val portFqn = "com.shared.security.application.ports.DashboardObserverAllowList"
        val staticFqn = "com.shared.security.application.ports.StaticDashboardObserverAllowList"
        val staticCompanionFqn = "$staticFqn\$Companion"
        // Allowed callers (prefix match — covers Kotlin's $inlined and $securityModule$
        // synthetic nested classes generated by `by inject<...>()` and Koin internals):
        val allowedPrefixes =
            listOf(
                "com.shared.security.adapters.inbound.http.ObservabilityRoutesKt",
                "com.shared.security.infrastructure.di.SecurityServiceModule",
                // ApplicationKt holds the `by inject<DashboardObserverAllowList>()` call
                // site that forwards the binding into installObservabilityRoutes(...).
                "com.shared.security.infrastructure.ApplicationKt",
            )
        val offenders =
            classes.filter { clazz ->
                clazz.directDependenciesFromSelf.any { dep ->
                    dep.targetClass.name == portFqn || dep.targetClass.name == staticFqn
                }
            }.map { it.name }
                .filter { name ->
                    name != portFqn &&
                        name != staticFqn &&
                        name != staticCompanionFqn &&
                        allowedPrefixes.none { prefix -> name.startsWith(prefix) }
                }
        check(offenders.isEmpty()) {
            "S-16 violation — DashboardObserverAllowList is referenced outside the allowed set: $offenders"
        }
    }

    /**
     * **S-20 — the mTLS-public allow-list passed to `installMtlsAuth` in `Application.kt`
     * is exactly `{"/v1/jwks", "/v1/health"}`.**
     *
     * Every other security-service route MUST be mTLS-gated. Adding a path to the
     * allow-list weakens an auditor-visible guarantee (FedRAMP AC-3) and updates the
     * security scorecard's Authentication row — both of which need explicit review.
     * This source-grep test forces that review by failing CI whenever the literal set
     * passed to `installMtlsAuth(publicPathPrefixes = …)` drifts from the canonical pair.
     *
     * The check is a string-literal inspection (same shape as S-15). It does NOT verify
     * the routing layer respects the gate — `MtlsAuthPluginTest` covers behavior.
     */
    @Test
    fun `S-20 installMtlsAuth public path allow-list is exactly the two documented routes`() {
        val expected = setOf("/v1/jwks", "/v1/health")
        val sourceFile =
            java.nio.file.Paths.get(
                "src", "main", "kotlin", "com", "shared", "security", "infrastructure",
                "Application.kt",
            )
        check(java.nio.file.Files.exists(sourceFile)) {
            "S-20 cannot find Application.kt at $sourceFile (test must run from infrastructure/)"
        }
        val text = java.nio.file.Files.readString(sourceFile)
        // Match the publicPathPrefixes argument value in the installMtlsAuth call. We
        // accept arbitrary whitespace/newlines inside setOf(...) but require a literal
        // setOf with double-quoted string entries.
        val regex =
            Regex(
                """publicPathPrefixes\s*=\s*setOf\(([^)]*)\)""",
                RegexOption.DOT_MATCHES_ALL,
            )
        val match =
            regex.find(text)
                ?: error(
                    "S-20 violation — could not find `publicPathPrefixes = setOf(...)` call in Application.kt. " +
                        "Either the wiring was removed (mTLS gate is now unconditional — update this test) " +
                        "or the call site was renamed.",
                )
        val literals =
            Regex("\"([^\"]+)\"").findAll(match.groupValues[1])
                .map { it.groupValues[1] }
                .toSet()
        check(literals == expected) {
            "S-20 violation — installMtlsAuth public-path allow-list drifted.\n" +
                "  expected: $expected\n" +
                "  found:    $literals\n" +
                "If you intentionally added/removed a public route, update the expected set here AND " +
                "update SECURITY_SCORECARD.md's Authentication row in the same commit."
        }
    }

    /**
     * **S-21 — `AuditEvent.detailJson` writers never embed row plaintext, DEK bytes, or
     * key material via string interpolation.**
     *
     * The audit chain is intentionally readable for forensics — that means whatever
     * lands in `detail_json` is visible to any operator with DB read access AND ships
     * to cold storage. The catalogued writers all construct structured metadata
     * (`{"endpoint":"…"}`, `{"reason":"…"}`, `{"kid":"…","alg":"…"}`, counts, etc.) but
     * a future writer that interpolates a row column or an unwrapped DEK into the JSON
     * would silently leak. This source-grep guards against that drift.
     *
     * The check looks for a `detailJson = ` assignment followed (on the same logical
     * line, with a small lookahead for multi-line raw strings) by an `${…}` template
     * expression referencing a banned identifier substring. Adding a new safe writer
     * doesn't trip this; adding `${plaintext}` / `${dek}` / `${row.body}` does.
     */
    @Test
    fun `S-21 detailJson writers do not interpolate plaintext or key material`() {
        val sourceRoot = java.nio.file.Paths.get("..").toAbsolutePath().normalize()
        check(java.nio.file.Files.isDirectory(sourceRoot)) {
            "S-21 cannot locate security-service repo root from $sourceRoot"
        }
        val violations =
            java.nio.file.Files.walk(sourceRoot).use { stream ->
                stream
                    .filter { java.nio.file.Files.isRegularFile(it) }
                    .filter { it.fileName.toString().endsWith(".kt") }
                    .filter { !it.toString().contains("/build/") }
                    .filter { !it.toString().contains("/test/") }
                    .toList()
            }.flatMap { violationsInDetailJsonAssignments(it) }
        check(violations.isEmpty()) {
            buildString {
                appendLine(
                    "S-21 violation — detailJson MUST NOT carry row plaintext, DEK bytes, or key " +
                        "material. The audit chain is operator-readable + ships to cold storage; " +
                        "anything in detail_json is effectively public to whoever can read the audit log.",
                )
                appendLine("Offenders:")
                violations.forEach { appendLine("  $it") }
            }
        }
    }

    private fun violationsInDetailJsonAssignments(path: java.nio.file.Path): List<String> {
        val text = java.nio.file.Files.readString(path)
        return S21_DETAIL_JSON_ASSIGNMENT
            .findAll(text)
            .flatMap { match -> violationsInAssignmentMatch(path, text, match) }
            .toList()
    }

    private fun violationsInAssignmentMatch(
        path: java.nio.file.Path,
        text: String,
        match: MatchResult,
    ): List<String> {
        val window = match.value.lowercase()
        val lineNumber = text.substring(0, match.range.first).count { it == '\n' } + 1
        return S21_BANNED_SUBSTRINGS
            .filter { banned -> Regex("""\$\{[^}]*$banned[^}]*\}""").containsMatchIn(window) }
            .map { banned ->
                "${path.fileName}:$lineNumber  banned token \"$banned\" " +
                    "interpolated into detailJson"
            }
    }

    private companion object {
        // `detailJson = ...` then up to ~400 chars within the same logical expression.
        // Generous window so multi-line raw strings + line continuations don't escape.
        private val S21_DETAIL_JSON_ASSIGNMENT =
            Regex("""detailJson\s*=\s*[^,)]{0,400}""", RegexOption.DOT_MATCHES_ALL)

        // Banned identifier substrings (case-insensitive). Mirrors operator-CLI S-19 set
        // plus key-material names that should never appear in audit writes.
        private val S21_BANNED_SUBSTRINGS =
            listOf(
                "plaintext",
                "decrypted",
                "unwrapped",
                "dekbytes",
                "deksecret",
                "privatekeybytes",
                "wrappedprivatekey",
                "clearbytes",
            )
    }
}
