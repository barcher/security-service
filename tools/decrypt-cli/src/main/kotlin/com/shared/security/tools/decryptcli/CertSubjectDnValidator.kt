package com.shared.security.tools.decryptcli

import java.security.MessageDigest

/**
 * Phase 14 Stream M (SKS-M14) — validates the operator's mTLS client cert subject DN
 * against the locked pattern from CLAUDE.md rule 28:
 *
 *     CN=workautomations-operator-decrypt-<email-hash>,O=WorkAutomations
 *
 * where `<email-hash>` is the first 16 hex chars of
 * `SHA-256(operator_email.lowercase().trim())`.
 *
 * **The pattern is locked at SKS-M14 sign-off and never changed** — 7-year FedRAMP
 * AU-11 audit retention accumulates rows tagged with this exact pattern.
 *
 * Called for two distinct purposes:
 *
 *   1. **Validate an externally-presented cert** (when the CLI loads the operator
 *      cert from `--mtls-cert`) — confirm the cert was minted for the operator
 *      claimed via `--operator-email`. This catches operator-email/cert mismatches
 *      that would otherwise produce a misleading audit trail.
 *   2. **Derive the expected DN from an operator email** (when we record the
 *      audit `actor_subject`) — the security-service CLI does NOT make outbound
 *      mTLS calls (it talks to its own DB + crypto-service directly), so the
 *      audit's `actor_subject` is computed from the email, NOT extracted from a
 *      live cert. The pattern compatibility check makes the two paths
 *      structurally equivalent.
 *
 * The hash is intentionally short (16 hex chars = 64 bits) for human readability
 * in audit logs and runbooks. Collision risk over a small operator set is
 * negligible; the email itself is the load-bearing identity, and the audit row
 * always carries the operator email in `detail_json`.
 */
object CertSubjectDnValidator {
    private val PATTERN =
        Regex(
            "^CN=workautomations-operator-decrypt-[0-9a-f]{$HASH_HEX_LENGTH}," +
                "O=WorkAutomations$",
        )

    fun matchesPattern(subjectDn: String): Boolean = PATTERN.matches(subjectDn)

    fun expectedSubjectDn(operatorEmail: String): String =
        "CN=workautomations-operator-decrypt-${emailHash(operatorEmail)},O=WorkAutomations"

    fun emailHash(operatorEmail: String): String {
        val canonical = operatorEmail.lowercase().trim()
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }.take(HASH_HEX_LENGTH)
    }

    fun validateMatchesOperator(
        subjectDn: String,
        operatorEmail: String,
    ): ValidationResult {
        if (!matchesPattern(subjectDn)) {
            return ValidationResult.PatternMismatch(subjectDn)
        }
        val expected = expectedSubjectDn(operatorEmail)
        if (subjectDn != expected) {
            return ValidationResult.EmailMismatch(presented = subjectDn, expected = expected)
        }
        return ValidationResult.Ok
    }

    sealed class ValidationResult {
        data object Ok : ValidationResult()

        data class PatternMismatch(val presentedDn: String) : ValidationResult()

        data class EmailMismatch(val presented: String, val expected: String) : ValidationResult()
    }

    private const val HASH_HEX_LENGTH = 16
}
