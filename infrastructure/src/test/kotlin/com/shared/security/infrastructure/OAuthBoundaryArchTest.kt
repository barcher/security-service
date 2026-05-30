package com.shared.security.infrastructure

import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import org.junit.jupiter.api.Test

/**
 * Boundary guards for the OAuth/OIDC provider (oauth proposal §8.4a).
 *
 * **ArchUnit-ID hygiene.** The proposal *proposed* IDs S-27 (http-oauth dependency direction)
 * and S-29 (no second crypto cornerstone module) from a v0.3-era scan that assumed S-22 was
 * the last claimed rule. The implementing PR re-scans and claims the then-next-free IDs; the
 * rule **names + intents are the contract, not the literal numbers**. The next-free IDs at
 * implementation time are **S-23** and **S-24**, claimed here:
 *
 * - **S-23** (proposal intent "S-27"): `http-oauth` depends only on `application` +
 *   `contracts/oauth-oidc`; it never imports any outbound adapter module.
 * - **S-24** (proposal intent "S-29"): no second crypto cornerstone module exists — the
 *   withdrawn `pqe-tokenization` proposal stays withdrawn and the only cornerstone is
 *   `adapters/outbound/crypto`.
 */
class OAuthBoundaryArchTest {
    private val classes =
        ClassFileImporter()
            .withImportOption(ImportOption.DoNotIncludeTests())
            .importPackages("com.shared.security")

    /**
     * **S-23 (proposal "S-27") — `http-oauth` depends only on `application` + `contracts`.**
     * The inbound OAuth HTTP module is a one-way leaf-ward dependency: it reaches the rest of
     * the system through application-layer ports + the pure wire contracts, never through an
     * outbound adapter (persistence / crypto / jwt-signing). Direct outbound access would let
     * a route bypass a use case and, e.g., touch the crypto envelope or DB directly.
     */
    @Test
    fun `S-23 http-oauth never depends on any outbound adapter module`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.adapters.inbound.oauth..")
            .should().dependOnClassesThat()
            .resideInAnyPackage("com.shared.security.adapters.outbound..")
            .allowEmptyShould(true)
            .check(classes)
    }

    /**
     * **S-23 (cont.) — `http-oauth` does not reach into the sibling `http` adapter either.**
     * The two inbound HTTP modules are independent; the OAuth surface composes via application
     * ports, not by importing the JWT/crypto route module's internals.
     */
    @Test
    fun `S-23 http-oauth never depends on the sibling inbound http module`() {
        noClasses()
            .that().resideInAPackage("com.shared.security.adapters.inbound.oauth..")
            .should().dependOnClassesThat()
            .resideInAnyPackage("com.shared.security.adapters.inbound.http..")
            .allowEmptyShould(true)
            .check(classes)
    }

    /**
     * **S-24 (proposal "S-29") — no second crypto cornerstone module.** PQE already exists as
     * the ML-KEM-768 KEK/DEK cornerstone in `adapters/outbound/crypto`; the OAuth layer
     * *composes with* it and introduces no new primitive/module (oauth proposal §4.4, §5). The
     * withdrawn v0.1 `pqe-tokenization` module must never reappear. This guard fails if any
     * class lands under a `pqe`/`tokenization` outbound package.
     */
    @Test
    fun `S-24 no second crypto cornerstone module exists`() {
        val forbidden =
            classes.filter { clazz ->
                val name = clazz.name
                name.startsWith("com.shared.security.adapters.outbound.") &&
                    (name.contains(".pqetokenization") || name.contains(".pqe.") || name.contains(".tokenization."))
            }.map { it.name }
        check(forbidden.isEmpty()) {
            "S-24 violation — a second crypto cornerstone / tokenization module appeared " +
                "(the withdrawn pqe-tokenization proposal must stay withdrawn): $forbidden"
        }
    }

    /**
     * **S-24 (cont.) — the OAuth token-mint signature path stays ES256-only and never imports
     * the ML-KEM cornerstone.** O.0 ships no token-mint yet, but the guard is forward-stated
     * for the OAuth application + http-oauth surface: neither may reference `MlKemService` /
     * `MlKemCryptoKeyService` (those live only in the crypto adapter; the signer is ES256 in
     * the isolated jwt-signing module). This composes with the existing S-8 / S-11 isolation.
     */
    @Test
    fun `S-24 oauth surface never references the ML-KEM cornerstone types`() {
        noClasses()
            .that().resideInAnyPackage(
                "com.shared.security.adapters.inbound.oauth..",
                "com.shared.security.application.usecases.oauth..",
            )
            .should().dependOnClassesThat()
            .haveSimpleName("MlKemService")
            .orShould().dependOnClassesThat()
            .haveSimpleName("MlKemCryptoKeyService")
            .allowEmptyShould(true)
            .check(classes)
    }
}
