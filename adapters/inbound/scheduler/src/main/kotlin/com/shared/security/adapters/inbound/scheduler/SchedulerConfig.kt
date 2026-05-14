package com.shared.security.adapters.inbound.scheduler

/**
 * Configuration for the Quartz schedule of every security-service job.
 *
 * All values are loaded from env vars at startup. Each `*_INTERVAL_*` is a positive integer
 * in the unit named by the suffix; the resolved cron schedule is logged at startup so
 * operators can verify their override took effect.
 */
data class SchedulerConfig(
    val enabled: Boolean,
    val kekRotationHealthIntervalMinutes: Int,
    val kekPriorTtlIntervalMinutes: Int,
    val dekRotationIntervalMinutes: Int,
    val auditLogShipperIntervalMinutes: Int,
    val auditRetentionIntervalHours: Int,
    val kekBackupVerifyIntervalHours: Int,
    val quiesceWindowHours: Int,
    val dekRotationBatchSize: Int,
) {
    init {
        if (enabled) {
            require(kekRotationHealthIntervalMinutes > 0) { "kekRotationHealth interval must be > 0" }
            require(kekPriorTtlIntervalMinutes > 0) { "kekPriorTtl interval must be > 0" }
            require(dekRotationIntervalMinutes > 0) { "dekRotation interval must be > 0" }
            require(auditLogShipperIntervalMinutes > 0) { "auditLogShipper interval must be > 0" }
            require(auditRetentionIntervalHours > 0) { "auditRetention interval must be > 0" }
            require(kekBackupVerifyIntervalHours > 0) { "kekBackupVerify interval must be > 0" }
            require(quiesceWindowHours > 0) { "quiesceWindow must be > 0" }
            require(dekRotationBatchSize in 1..MAX_BATCH) { "dekRotationBatchSize must be 1..$MAX_BATCH" }
        }
    }

    companion object {
        const val ENV_ENABLED = "SECURITY_SCHEDULER_ENABLED"
        const val ENV_KEK_HEALTH_MIN = "SECURITY_KEK_HEALTH_INTERVAL_MINUTES"
        const val ENV_KEK_TTL_MIN = "SECURITY_KEK_PRIOR_TTL_INTERVAL_MINUTES"
        const val ENV_DEK_ROTATION_MIN = "SECURITY_DEK_ROTATION_INTERVAL_MINUTES"
        const val ENV_AUDIT_SHIPPER_MIN = "SECURITY_AUDIT_SHIPPER_INTERVAL_MINUTES"
        const val ENV_AUDIT_RETENTION_HRS = "SECURITY_AUDIT_RETENTION_INTERVAL_HOURS"
        const val ENV_BACKUP_VERIFY_HRS = "SECURITY_KEK_BACKUP_VERIFY_INTERVAL_HOURS"
        const val ENV_QUIESCE_HRS = "SECURITY_KEK_QUIESCE_WINDOW_HOURS"
        const val ENV_DEK_BATCH = "SECURITY_DEK_ROTATION_BATCH_SIZE"

        const val DEFAULT_HEALTH_MIN = 60
        const val DEFAULT_TTL_MIN = 60
        const val DEFAULT_DEK_ROTATION_MIN = 10_080 // weekly
        const val DEFAULT_AUDIT_SHIPPER_MIN = 60
        const val DEFAULT_AUDIT_RETENTION_HRS = 24
        const val DEFAULT_BACKUP_VERIFY_HRS = 24
        const val DEFAULT_QUIESCE_HRS = 24
        const val DEFAULT_DEK_BATCH = 100
        private const val MAX_BATCH = 10_000

        fun fromEnv(env: (String) -> String? = System::getenv): SchedulerConfig {
            val enabled = parseBoolean(env(ENV_ENABLED), default = false)
            return SchedulerConfig(
                enabled = enabled,
                kekRotationHealthIntervalMinutes =
                    parseInt(env(ENV_KEK_HEALTH_MIN), DEFAULT_HEALTH_MIN, ENV_KEK_HEALTH_MIN),
                kekPriorTtlIntervalMinutes =
                    parseInt(env(ENV_KEK_TTL_MIN), DEFAULT_TTL_MIN, ENV_KEK_TTL_MIN),
                dekRotationIntervalMinutes =
                    parseInt(env(ENV_DEK_ROTATION_MIN), DEFAULT_DEK_ROTATION_MIN, ENV_DEK_ROTATION_MIN),
                auditLogShipperIntervalMinutes =
                    parseInt(env(ENV_AUDIT_SHIPPER_MIN), DEFAULT_AUDIT_SHIPPER_MIN, ENV_AUDIT_SHIPPER_MIN),
                auditRetentionIntervalHours =
                    parseInt(env(ENV_AUDIT_RETENTION_HRS), DEFAULT_AUDIT_RETENTION_HRS, ENV_AUDIT_RETENTION_HRS),
                kekBackupVerifyIntervalHours =
                    parseInt(env(ENV_BACKUP_VERIFY_HRS), DEFAULT_BACKUP_VERIFY_HRS, ENV_BACKUP_VERIFY_HRS),
                quiesceWindowHours = parseInt(env(ENV_QUIESCE_HRS), DEFAULT_QUIESCE_HRS, ENV_QUIESCE_HRS),
                dekRotationBatchSize = parseInt(env(ENV_DEK_BATCH), DEFAULT_DEK_BATCH, ENV_DEK_BATCH),
            )
        }

        private fun parseBoolean(
            raw: String?,
            default: Boolean,
        ): Boolean =
            when (raw?.trim()?.lowercase()) {
                null, "" -> default
                "true", "1", "yes", "on" -> true
                "false", "0", "no", "off" -> false
                else -> throw SchedulerConfigException(
                    "$ENV_ENABLED must be true/false/1/0/yes/no/on/off; got '$raw'",
                )
            }

        private fun parseInt(
            raw: String?,
            default: Int,
            name: String,
        ): Int {
            if (raw.isNullOrBlank()) return default
            return raw.trim().toIntOrNull()
                ?: throw SchedulerConfigException("$name must be an integer; got '$raw'")
        }
    }
}

class SchedulerConfigException(message: String) : RuntimeException(message)
