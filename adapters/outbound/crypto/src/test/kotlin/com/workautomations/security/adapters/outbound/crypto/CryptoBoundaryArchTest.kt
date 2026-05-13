package com.workautomations.security.adapters.outbound.crypto

import com.tngtech.archunit.base.DescribedPredicate
import com.tngtech.archunit.core.domain.JavaClass
import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import org.junit.jupiter.api.Test

/**
 * Boundary rules for the security-service crypto module.
 *
 * Maps to proposal §6.2 ArchUnit rules S-1, S-2, S-3. S-9 (cross-repo port byte-identity
 * with scaffold) is asserted in a sibling test class that runs in `:infrastructure:test`
 * because it needs filesystem access to both repos.
 */
class CryptoBoundaryArchTest {
    private val cryptoClasses =
        ClassFileImporter()
            .withImportOption(ImportOption.DoNotIncludeTests())
            .importPackages("com.workautomations.security.adapters.outbound.crypto")

    @Test
    fun `S-1 crypto module must not depend on domain`() {
        noClasses()
            .that().resideInAPackage("com.workautomations.security.adapters.outbound.crypto..")
            .should().dependOnClassesThat()
            .resideInAPackage("com.workautomations.security.domain..")
            .allowEmptyShould(true)
            .check(cryptoClasses)
    }

    @Test
    fun `S-2 crypto module must not depend on persistence adapter`() {
        noClasses()
            .that().resideInAPackage("com.workautomations.security.adapters.outbound.crypto..")
            .should().dependOnClassesThat()
            .resideInAPackage("com.workautomations.security.adapters.outbound.persistence..")
            .allowEmptyShould(true)
            .check(cryptoClasses)
    }

    @Test
    fun `S-3 only MlKemCryptoKeyService NoOpCryptoKeyService may reference MlKemService`() {
        // Match by enclosing top-level class name (not simple name), so Kotlin companion
        // objects and synthetic lambda classes nested inside the three allowed types are
        // excluded along with the types themselves. Tests are excluded via DoNotIncludeTests.
        val allowedTopLevelNames =
            setOf(
                "MlKemCryptoKeyService",
                "MlKemService",
                "NoOpCryptoKeyService",
            )
        noClasses()
            .that().resideInAPackage("com.workautomations.security.adapters.outbound.crypto..")
            .and(
                object : DescribedPredicate<JavaClass>("is not part of an allowed top-level class") {
                    override fun test(javaClass: JavaClass): Boolean {
                        val topLevelName = javaClass.fullName.substringAfterLast('.').substringBefore('$')
                        return topLevelName !in allowedTopLevelNames
                    }
                },
            )
            .should().dependOnClassesThat().haveSimpleName("MlKemService")
            // Currently vacuous (only the allowed types exist in main); rule is a forward
            // guard for when new production classes land in this module.
            .allowEmptyShould(true)
            .check(cryptoClasses)
    }
}
