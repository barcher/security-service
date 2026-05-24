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
}
