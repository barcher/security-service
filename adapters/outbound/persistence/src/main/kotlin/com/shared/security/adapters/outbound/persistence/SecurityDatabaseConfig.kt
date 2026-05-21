package com.shared.security.adapters.outbound.persistence

/**
 * Database connection configuration for the security service's own MySQL.
 *
 * Per Phase 14 §3.1 + §3.2, the security service has its **own MySQL instance**, separate
 * Hikari pool, and separate Flyway migration root. The monolith's DB is never read or
 * written from this service. The configuration here is loaded from env vars only — there is
 * no fallback file or HOCON path.
 *
 * Env vars (typically sourced from a k8s ConfigMap or docker-compose `environment`):
 *
 * | Var | Default | Notes |
 * |-----|---------|-------|
 * | `SECURITY_DB_URL` | `jdbc:mysql://security-mysql:3306/security_keys` | Stream E adds the matching docker-compose service. |
 * | `SECURITY_DB_USER` | `security` | |
 * | `SECURITY_DB_PASSWORD` | (none) | Required when [enabled]. Fail-closed on missing. |
 * | `SECURITY_DB_POOL_SIZE` | `5` | HikariCP `maximumPoolSize`. |
 * | `SECURITY_DB_ENABLED` | `true` | `false` is an explicit dev-only opt-out that wires the SLF4J fallback adapter (no tamper-evident audit chain). |
 *
 * **Default flipped to `true` in SKS-E08** (2026-05-15). The Stream-B-era default of
 * `false` was a safety to let the service boot without MySQL during early development,
 * but it silently downgraded audit posture once the DB was available — operators were
 * getting `Slf4jAuditLogAdapter` (in-memory log fallback) when they expected the real
 * HMAC-chained adapter. The default now matches operational expectations; pass
 * `SECURITY_DB_ENABLED=false` explicitly for tests or for boot-without-MySQL smoke checks.
 */
data class SecurityDatabaseConfig(
    val jdbcUrl: String,
    val user: String,
    val password: String,
    val poolSize: Int,
) {
    init {
        require(jdbcUrl.isNotBlank()) { "SECURITY_DB_URL must not be blank" }
        require(user.isNotBlank()) { "SECURITY_DB_USER must not be blank" }
        require(password.isNotBlank()) { "SECURITY_DB_PASSWORD must not be blank" }
        require(poolSize in 1..MAX_POOL_SIZE) { "SECURITY_DB_POOL_SIZE must be in 1..$MAX_POOL_SIZE, got $poolSize" }
    }

    companion object {
        const val ENV_ENABLED = "SECURITY_DB_ENABLED"
        const val ENV_URL = "SECURITY_DB_URL"
        const val ENV_USER = "SECURITY_DB_USER"
        const val ENV_PASSWORD = "SECURITY_DB_PASSWORD"
        const val ENV_POOL_SIZE = "SECURITY_DB_POOL_SIZE"

        const val DEFAULT_URL = "jdbc:mysql://security-mysql:3306/security_keys"
        const val DEFAULT_USER = "security"
        const val DEFAULT_POOL_SIZE = 5
        private const val MAX_POOL_SIZE = 50

        /**
         * Whether the DB-backed adapters should be wired. When this returns false, callers
         * must keep the Stream-B SLF4J fallback bindings live (the audit log writes to slf4j
         * INFO and no `keks` / `deks` table state is touched).
         */
        fun isEnabled(env: (String) -> String? = System::getenv): Boolean = parseBoolean(env(ENV_ENABLED), true)

        /**
         * Load config from the process environment. Throws [SecurityDatabaseConfigException]
         * if `SECURITY_DB_ENABLED=true` but a required var is missing or invalid; misconfig
         * surfaces at startup, never at first traffic.
         */
        @Suppress("ThrowsCount") // each branch maps a distinct misconfig to a clear startup error
        fun fromEnv(env: (String) -> String? = System::getenv): SecurityDatabaseConfig {
            val url = env(ENV_URL)?.takeIf { it.isNotBlank() } ?: DEFAULT_URL
            val user = env(ENV_USER)?.takeIf { it.isNotBlank() } ?: DEFAULT_USER
            val password =
                env(ENV_PASSWORD)?.takeIf { it.isNotBlank() }
                    ?: throw SecurityDatabaseConfigException("$ENV_PASSWORD is required when $ENV_ENABLED=true")
            val poolSize =
                env(ENV_POOL_SIZE)?.takeIf { it.isNotBlank() }?.let {
                    it.toIntOrNull()
                        ?: throw SecurityDatabaseConfigException("$ENV_POOL_SIZE must be an integer; got '$it'")
                } ?: DEFAULT_POOL_SIZE

            return runCatching {
                SecurityDatabaseConfig(jdbcUrl = url, user = user, password = password, poolSize = poolSize)
            }.getOrElse {
                throw SecurityDatabaseConfigException(it.message ?: "invalid SecurityDatabaseConfig", it)
            }
        }

        private fun parseBoolean(
            raw: String?,
            default: Boolean,
        ): Boolean =
            when (raw?.trim()?.lowercase()) {
                null, "" -> default
                "true", "1", "yes", "on" -> true
                "false", "0", "no", "off" -> false
                else -> throw SecurityDatabaseConfigException(
                    "$ENV_ENABLED must be one of true/false/1/0/yes/no/on/off; got '$raw'",
                )
            }
    }
}

class SecurityDatabaseConfigException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
