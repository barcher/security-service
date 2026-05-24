package com.shared.security.tools.decryptcli

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 14 Stream M (SKS-M14) — DN pattern lock is the load-bearing invariant
 * (CLAUDE.md rule 28 — 7-year FedRAMP AU-11 retention depends on the format).
 */
class CertSubjectDnValidatorTest {
    @Test
    fun `email hash is first 16 hex chars of sha-256`() {
        val hash = CertSubjectDnValidator.emailHash("ops-alice@example.com")
        assertEquals(16, hash.length)
        assertTrue(hash.all { it.isDigit() || it in 'a'..'f' })
    }

    @Test
    fun `email hash is canonical lowercase trim`() {
        val a = CertSubjectDnValidator.emailHash("OPS-Alice@Example.com  ")
        val b = CertSubjectDnValidator.emailHash("ops-alice@example.com")
        assertEquals(a, b)
    }

    @Test
    fun `expected DN matches the locked pattern`() {
        val dn = CertSubjectDnValidator.expectedSubjectDn("ops-alice@example.com")
        assertTrue(CertSubjectDnValidator.matchesPattern(dn), "expected DN must match locked pattern: $dn")
    }

    @Test
    fun `matchesPattern rejects operational monolith DN`() {
        assertFalse(CertSubjectDnValidator.matchesPattern("CN=workautomations-monolith,O=WorkAutomations"))
    }

    @Test
    fun `matchesPattern rejects dashboard observer DN`() {
        assertFalse(
            CertSubjectDnValidator.matchesPattern(
                "CN=workautomations-dashboard-observer,O=WorkAutomations",
            ),
        )
    }

    @Test
    fun `matchesPattern rejects DN with extra organisational unit`() {
        assertFalse(
            CertSubjectDnValidator.matchesPattern(
                "CN=workautomations-operator-decrypt-0123456789abcdef," +
                    "OU=Engineering,O=WorkAutomations",
            ),
        )
    }

    @Test
    fun `validateMatchesOperator flags an email mismatch even when pattern matches`() {
        val correct = CertSubjectDnValidator.expectedSubjectDn("ops-alice@example.com")
        val different = CertSubjectDnValidator.expectedSubjectDn("ops-bob@example.com")
        assertNotEquals(correct, different, "two different emails must hash to different DNs")
        val result = CertSubjectDnValidator.validateMatchesOperator(different, "ops-alice@example.com")
        assertTrue(result is CertSubjectDnValidator.ValidationResult.EmailMismatch)
    }
}
