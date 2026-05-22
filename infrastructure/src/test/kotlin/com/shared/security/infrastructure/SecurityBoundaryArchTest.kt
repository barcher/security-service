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
}
