package com.shared.security.tools.decryptcli

import com.shared.security.adapters.outbound.persistence.ExposedDekRepository
import com.shared.security.adapters.outbound.persistence.ExposedJwtSigningKeyRepository
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.audit.AuditChainHasher
import com.shared.security.adapters.outbound.persistence.audit.AuditHmacKeyProvider
import com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogQueryRepository
import com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository

/**
 * Phase 14 Stream M (SKS-M18, M.2 portion) — production runtime wiring for the
 * operator decrypt CLI.
 *
 * Reads the security-service's standard env vars (`SECURITY_DB_*` for the JDBC
 * pool; `AUDIT_HMAC_KEY` for the audit-chain hasher) and constructs the four
 * adapter instances the CLI needs. The operator runs the CLI on a workstation
 * or jump-host with these env vars sourced from a copy of the security-service
 * `.env` — see `security-service/docs/OPERATOR_DECRYPT_RUNBOOK.md`.
 *
 * The bound MySQL connection is the same physical database as the running
 * security-service uses. Writes are limited to a single `OPERATOR_DECRYPT_RUN`
 * audit row per invocation (CLAUDE.md rule 26); reads are limited to the
 * security-service-owned tables enumerated in `Executors.kt`.
 *
 * **The pool is leaked on purpose.** This CLI is a single-shot process; the
 * JVM exits at the end of `main()` and the OS reclaims the connection. Wiring
 * a shutdown hook would add complexity for no operator benefit.
 */
internal object ProductionCliRuntime {
    fun boot(): CliRuntime {
        val dbConfig = SecurityDatabaseConfig.fromEnv()
        val database = SecurityDatabase.create(dbConfig)
        val hmacKey = AuditHmacKeyProvider.fromEnv()
        val hasher = AuditChainHasher(hmacKey)

        val auditWriter = ExposedAuditLogRepository(database.database, hasher)
        val auditQuery = ExposedAuditLogQueryRepository(database.database)
        val dekRepo = ExposedDekRepository(database.database)
        val jwtRepo = ExposedJwtSigningKeyRepository(database.database)

        return CliRuntime(
            auditLog = auditWriter,
            auditLogQuery = auditQuery,
            dekRepository = dekRepo,
            jwtRepository = jwtRepo,
        )
    }
}
