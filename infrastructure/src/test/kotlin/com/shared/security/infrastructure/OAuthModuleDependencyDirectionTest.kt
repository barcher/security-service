package com.shared.security.infrastructure

import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import org.junit.jupiter.api.Test

/**
 * `OAuthModuleDependencyDirectionTest` (oauth proposal §8.4a) — asserts the one-way OAuth
 * dependency graph `http-oauth → application → domain`, the leaf position of
 * `contracts/oauth-oidc`, and the absence of any reverse / outbound edge.
 *
 * This is the named unit test the O.0 acceptance criteria call for; it complements the S-23
 * ArchUnit rule in [OAuthBoundaryArchTest] by pinning the *direction* of the graph, not just
 * the absence of forbidden imports.
 */
class OAuthModuleDependencyDirectionTest {
    private val imported =
        ClassFileImporter()
            .withImportOption(ImportOption.DoNotIncludeTests())
            .importPackages("com.shared.security")

    @Test
    fun `oauth application use cases depend only on domain and application, never inbound or outbound adapters`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.application.usecases.oauth..")
            .should().dependOnClassesThat()
            .resideInAnyPackage(
                "com.shared.security.adapters.inbound..",
                "com.shared.security.adapters.outbound..",
                "com.shared.security.infrastructure..",
            )
            .allowEmptyShould(true)
            .check(imported)
    }

    @Test
    fun `contracts oauth-oidc is a leaf - it depends on no other security module`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.contracts.oauth..")
            .should().dependOnClassesThat()
            .resideInAnyPackage(
                "com.shared.security.domain..",
                "com.shared.security.application..",
                "com.shared.security.adapters..",
                "com.shared.security.infrastructure..",
            )
            .allowEmptyShould(true)
            .check(imported)
    }

    @Test
    fun `http-oauth routes depend on application and contracts, in the forward direction only`() {
        // Forward edges http-oauth -> {application, contracts, domain} are allowed; any edge
        // to an outbound adapter or to infrastructure is a direction violation.
        classes()
            .that().resideInAPackage("com.shared.security.adapters.inbound.oauth..")
            .should().onlyDependOnClassesThat()
            .resideInAnyPackage(
                "com.shared.security.adapters.inbound.oauth..",
                "com.shared.security.application..",
                "com.shared.security.contracts.oauth..",
                "com.shared.security.domain..",
                // Framework + stdlib the route handler legitimately uses.
                "io.ktor..",
                "kotlinx..",
                "kotlin..",
                "java..",
                "org.slf4j..",
                // Kotlin emits @NotNull/@Nullable parameter annotations from this package.
                "org.jetbrains.annotations..",
            )
            .allowEmptyShould(true)
            .check(imported)
    }
}
