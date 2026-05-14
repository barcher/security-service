package com.shared.security.adapters.outbound.persistence.audit

import java.util.Base64

/**
 * Loads the `AUDIT_HMAC_KEY` secret from the process environment.
 *
 * The key is base64-encoded raw bytes; minimum 32 bytes after decoding. Loaded once at
 * startup and held in memory only. Distinct from any KEK material per proposal §10 — a
 * leak of the audit HMAC key compromises chain integrity but does not expose plaintext
 * DEKs, and vice-versa.
 */
object AuditHmacKeyProvider {
    const val ENV_NAME = "AUDIT_HMAC_KEY"

    @Suppress("ThrowsCount") // each branch maps a distinct misconfig to a clear startup error
    fun fromEnv(env: (String) -> String? = System::getenv): ByteArray {
        val raw =
            env(ENV_NAME)?.takeIf { it.isNotBlank() }
                ?: throw AuditHmacKeyMissingException("$ENV_NAME is required when SECURITY_DB_ENABLED=true")
        val decoded =
            runCatching { Base64.getDecoder().decode(raw.trim()) }.getOrElse {
                throw AuditHmacKeyMissingException("$ENV_NAME must be valid base64", it)
            }
        if (decoded.size < AuditChainHasher.MIN_KEY_BYTES) {
            throw AuditHmacKeyMissingException(
                "$ENV_NAME decodes to ${decoded.size} bytes; need at least ${AuditChainHasher.MIN_KEY_BYTES}",
            )
        }
        return decoded
    }
}

class AuditHmacKeyMissingException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
