package com.shared.security.infrastructure.config

import com.shared.security.application.ports.JwtAudienceAllowList
import org.slf4j.LoggerFactory
import java.security.MessageDigest

/**
 * Env-backed Gate-2 caller-auth adapter.
 *
 * Source format — a single env var `SECURITY_JWT_AUDIENCE_ALLOWLIST` holds a
 * comma-separated list of `<subject-dn-hash>=<audience>` pairs. The subject-DN hash is
 * the first 16 lowercase hex chars of `SHA-256(subjectDn.lowercase().trim())`. Hashing
 * the DN (rather than embedding it verbatim) keeps env vars short and avoids
 * issues with whitespace / unusual characters in DNs.
 *
 * Example:
 * ```
 * SECURITY_JWT_AUDIENCE_ALLOWLIST="a1b2c3d4e5f60718=workautomations-api,a1b2c3d4e5f60718=workautomations-internal,f9e8d7c6b5a40312=financial-api"
 * ```
 *
 * A subject DN with no entries denies every audience. A known subject with no entry
 * for the requested audience also denies. Deny-by-default in all cases.
 */
class EnvJwtAudienceAllowList(
    rawConfigValue: String?,
) : JwtAudienceAllowList {
    private val map: Map<String, Set<String>> = parse(rawConfigValue)

    override fun isAllowed(
        subjectDn: String,
        audience: String,
    ): Boolean {
        val hash = hashSubject(subjectDn)
        val allowed = map[hash] ?: return false
        return audience in allowed
    }

    private fun parse(raw: String?): Map<String, Set<String>> {
        if (raw.isNullOrBlank()) {
            LoggerFactory.getLogger(EnvJwtAudienceAllowList::class.java).warn(
                "SECURITY_JWT_AUDIENCE_ALLOWLIST is empty; every JWT sign request will be denied at Gate 2",
            )
            return emptyMap()
        }
        val accumulator = mutableMapOf<String, MutableSet<String>>()
        raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach { pair ->
            val idx = pair.indexOf('=')
            require(idx > 0 && idx < pair.length - 1) {
                "Malformed SECURITY_JWT_AUDIENCE_ALLOWLIST entry '$pair' " +
                    "(expected '<subject-dn-hash>=<audience>')"
            }
            val hash = pair.substring(0, idx).lowercase()
            val audience = pair.substring(idx + 1)
            require(hash.matches(HEX_HASH_REGEX)) {
                "Subject-DN hash '$hash' is not 16 lowercase hex chars"
            }
            accumulator.getOrPut(hash) { mutableSetOf() }.add(audience)
        }
        return accumulator
    }

    private companion object {
        private val HEX_HASH_REGEX = Regex("^[0-9a-f]{16}$")
    }
}

/**
 * Helper for callers who need to derive the subject-DN hash for allow-list config —
 * matches the hash function inside [EnvJwtAudienceAllowList].
 */
fun hashSubject(subjectDn: String): String {
    val normalized = subjectDn.lowercase().trim()
    val digest = MessageDigest.getInstance("SHA-256").digest(normalized.toByteArray(Charsets.UTF_8))
    return digest.copyOfRange(0, 8).joinToString("") { "%02x".format(it) }
}
