package com.shared.security.infrastructure.di

import com.shared.security.adapters.inbound.http.auth.DenyAllPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.PeerCertChainExtractor
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.adapters.outbound.persistence.audit.AuditChainHasher
import com.shared.security.adapters.outbound.persistence.audit.AuditHmacKeyProvider
import com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.infrastructure.audit.Slf4jAuditLogAdapter
import com.shared.security.infrastructure.config.RateLimitConfig
import kotlinx.datetime.Clock
import org.koin.dsl.module
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("com.shared.security.infrastructure.di.SecurityServiceModule")

/**
 * Composition root for the security service.
 *
 * **AuditLogPort binding** is chosen at startup:
 *
 * - `SECURITY_DB_ENABLED=false` (default through Stream B; flipped to `true` in Stream E's
 *   docker-compose env): falls back to [Slf4jAuditLogAdapter]. Events go to slf4j INFO.
 * - `SECURITY_DB_ENABLED=true`: binds [ExposedAuditLogRepository] with the HMAC-SHA-512
 *   chain. `SECURITY_DB_PASSWORD` and `AUDIT_HMAC_KEY` env vars are required in this mode —
 *   misconfig fails at startup with a clear exception.
 *
 * **PeerCertChainExtractor** is bound to [DenyAllPeerCertChainExtractor] until Stream E
 * swaps in the real extractor (Netty SSL session reader or Linkerd sidecar header reader).
 * This is intentional fail-closed wiring — we'd rather every endpoint return 401 than
 * silently accept unauthenticated traffic.
 *
 * **RateLimitConfig + PerSubjectRateLimiter** are always constructed; the route layer
 * (Application.kt) only wires the limiter into `/v1/dek/unwrap` when
 * [RateLimitConfig.enabled] is true. See [RateLimitConfig] KDoc for the env-var contract.
 */
val securityServiceModule =
    module {
        single<PeerCertChainExtractor> { DenyAllPeerCertChainExtractor() }
        single { RateLimitConfig.fromEnv() }
        single {
            val config = get<RateLimitConfig>()
            val capacity = if (config.enabled) config.capacity else 1.0
            val refill = if (config.enabled) config.refillTokensPerSecond else 1.0
            PerSubjectRateLimiter(capacity = capacity, refillTokensPerSecond = refill, clock = Clock.System)
        }
        single<AuditLogPort> { buildAuditLogAdapter() }
    }

/**
 * Decides between the SLF4J fallback and the persistent HMAC-chained adapter based on
 * `SECURITY_DB_ENABLED`. Side-effects: starts a Hikari pool and runs Flyway migrations
 * when DB-backed mode is selected. Idempotent across startup retries.
 */
private fun buildAuditLogAdapter(): AuditLogPort {
    if (!SecurityDatabaseConfig.isEnabled()) {
        logger.info("SECURITY_DB_ENABLED=false → using Slf4jAuditLogAdapter (no persistent audit chain)")
        return Slf4jAuditLogAdapter()
    }
    val dbConfig = SecurityDatabaseConfig.fromEnv()
    val database = SecurityDatabase.create(dbConfig)
    SecurityFlywayMigrator(database.dataSource).migrate()
    val hmacKey = AuditHmacKeyProvider.fromEnv()
    val hasher = AuditChainHasher(hmacKey)
    logger.info("SECURITY_DB_ENABLED=true → binding ExposedAuditLogRepository with HMAC-SHA-512 chain")
    return ExposedAuditLogRepository(database.database, hasher)
}
