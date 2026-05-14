package com.shared.security.infrastructure.config

/**
 * Configuration for the per-subject rate limiter on `/v1/dek/unwrap`.
 *
 * Loaded from env vars (typically sourced from a k8s ConfigMap or docker-compose `environment`):
 *
 * | Env var                                          | Default | Effect when set |
 * |--------------------------------------------------|---------|-----------------|
 * | `SECURITY_UNWRAP_RATE_LIMIT_ENABLED`             | `true`  | `false` disables the limiter entirely (all calls pass; no audit on overflow). |
 * | `SECURITY_UNWRAP_RATE_LIMIT_CAPACITY`            | `5`     | Token-bucket capacity per subject DN. Must be > 0. |
 * | `SECURITY_UNWRAP_RATE_LIMIT_REFILL_PER_SECOND`   | `1.0`   | Refill rate in tokens / second. Must be > 0. |
 *
 * **Operator note:** the limiter is **strictly local-process** in Stream B. Horizontal scale-out
 * lands in Stream C with the persistent audit chain and a shared limiter store. Until then, each
 * security-service replica has its own buckets — a 5/s configured limit per replica becomes
 * `5/s × replicas` effective when traffic is load-balanced across them. Set the per-replica
 * limit conservatively when scaling beyond a single instance.
 */
data class RateLimitConfig(
    val enabled: Boolean,
    val capacity: Double,
    val refillTokensPerSecond: Double,
) {
    init {
        if (enabled) {
            require(capacity > 0) { "capacity must be > 0 when enabled, got $capacity" }
            require(refillTokensPerSecond > 0) {
                "refillTokensPerSecond must be > 0 when enabled, got $refillTokensPerSecond"
            }
        }
    }

    companion object {
        const val ENV_ENABLED = "SECURITY_UNWRAP_RATE_LIMIT_ENABLED"
        const val ENV_CAPACITY = "SECURITY_UNWRAP_RATE_LIMIT_CAPACITY"
        const val ENV_REFILL = "SECURITY_UNWRAP_RATE_LIMIT_REFILL_PER_SECOND"

        private const val DEFAULT_CAPACITY = 5.0
        private const val DEFAULT_REFILL_PER_SECOND = 1.0

        /**
         * Load config from the process environment. Returns the defaults when env vars are absent.
         *
         * Parse failures (non-numeric capacity / refill rate, capacity ≤ 0, refill ≤ 0) raise
         * [RateLimitConfigException] so misconfiguration surfaces at startup rather than at first
         * traffic. The disabled mode (`SECURITY_UNWRAP_RATE_LIMIT_ENABLED=false`) bypasses
         * capacity/refill validation.
         */
        fun fromEnv(env: (String) -> String? = System::getenv): RateLimitConfig {
            val enabled = parseBoolean(env(ENV_ENABLED), default = true)
            if (!enabled) {
                // Sentinel values; never read by the limiter.
                return RateLimitConfig(
                    enabled = false,
                    capacity = DEFAULT_CAPACITY,
                    refillTokensPerSecond = DEFAULT_REFILL_PER_SECOND,
                )
            }
            val capacity = parsePositiveDouble(env(ENV_CAPACITY), default = DEFAULT_CAPACITY, name = ENV_CAPACITY)
            val refill =
                parsePositiveDouble(env(ENV_REFILL), default = DEFAULT_REFILL_PER_SECOND, name = ENV_REFILL)
            return RateLimitConfig(enabled = true, capacity = capacity, refillTokensPerSecond = refill)
        }

        private fun parseBoolean(
            raw: String?,
            default: Boolean,
        ): Boolean =
            when (raw?.trim()?.lowercase()) {
                null, "" -> default
                "true", "1", "yes", "on" -> true
                "false", "0", "no", "off" -> false
                else -> throw RateLimitConfigException(
                    "$ENV_ENABLED must be one of true/false/1/0/yes/no/on/off; got '$raw'",
                )
            }

        private fun parsePositiveDouble(
            raw: String?,
            default: Double,
            name: String,
        ): Double {
            if (raw.isNullOrBlank()) return default
            val parsed =
                raw.trim().toDoubleOrNull()
                    ?: throw RateLimitConfigException("$name must be a number; got '$raw'")
            if (parsed <= 0) {
                throw RateLimitConfigException("$name must be > 0; got $parsed")
            }
            return parsed
        }
    }
}

class RateLimitConfigException(message: String) : RuntimeException(message)
