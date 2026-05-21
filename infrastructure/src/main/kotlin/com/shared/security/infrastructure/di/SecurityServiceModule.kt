package com.shared.security.infrastructure.di

import com.shared.security.adapters.inbound.http.auth.DenyAllPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.NettySslPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.PeerCertChainExtractor
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.adapters.outbound.crypto.MlKemCryptoKeyService
import com.shared.security.adapters.outbound.crypto.NoOpCryptoKeyService
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.adapters.outbound.persistence.audit.AuditChainHasher
import com.shared.security.adapters.outbound.persistence.audit.AuditHmacKeyProvider
import com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
import com.shared.security.application.ports.AdminAllowList
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.StaticAdminAllowList
import com.shared.security.application.usecases.GenerateDekUseCase
import com.shared.security.application.usecases.GenerateNewKekPairUseCase
import com.shared.security.application.usecases.GetKeyStatusUseCase
import com.shared.security.application.usecases.RewrapDekUseCase
import com.shared.security.application.usecases.UnwrapDekUseCase
import com.shared.security.application.usecases.WrapDekUseCase
import com.shared.security.infrastructure.audit.Slf4jAuditLogAdapter
import com.shared.security.infrastructure.config.RateLimitConfig
import com.shared.security.infrastructure.tls.MtlsConfig
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
        single<PeerCertChainExtractor> {
            // When MtlsConfig is loadable from env, TLS termination is active in
            // Application.kt and we can read peer certs from the Netty SSL session.
            // Otherwise fail-closed: every request → 401 (better than silent acceptance).
            if (MtlsConfig.fromEnv() != null) {
                logger.info("PeerCertChainExtractor → NettySslPeerCertChainExtractor (mTLS active)")
                NettySslPeerCertChainExtractor()
            } else {
                logger.warn(
                    "PeerCertChainExtractor → DenyAllPeerCertChainExtractor (MtlsConfig env vars unset; " +
                        "every request will be rejected with 401). Set SECURITY_SERVICE_KEYSTORE_PATH + " +
                        "SECURITY_SERVICE_TRUSTSTORE_PATH to enable mTLS.",
                )
                DenyAllPeerCertChainExtractor()
            }
        }
        single { RateLimitConfig.fromEnv() }
        single {
            val config = get<RateLimitConfig>()
            val capacity = if (config.enabled) config.capacity else 1.0
            val refill = if (config.enabled) config.refillTokensPerSecond else 1.0
            PerSubjectRateLimiter(capacity = capacity, refillTokensPerSecond = refill, clock = Clock.System)
        }
        single<AuditLogPort> { buildAuditLogAdapter() }

        // Crypto layer — wire CryptoKeyServicePort + use cases.
        // The real ML-KEM service is bound when at least one of the suffixed env-var pairs
        // is present:
        //   - ML_KEM_PUBLIC_KEY_CURRENT  + ML_KEM_PRIVATE_KEY_CURRENT  (current KEK)
        //   - ML_KEM_PUBLIC_KEY_LEGACY_V0 + ML_KEM_PRIVATE_KEY_LEGACY_V0 (legacy unwrap-only)
        // If only the legacy pair is set, /v1/dek/generate|wrap|rewrap|key-status will throw;
        // /v1/dek/unwrap on legacy-tagged DEKs still works. Unsuffixed ML_KEM_PUBLIC_KEY /
        // ML_KEM_PRIVATE_KEY are explicitly IGNORED (logged once at startup).
        single<CryptoKeyServicePort> {
            if (MlKemCryptoKeyService.unsuffixedEnvVarsPresent()) {
                logger.warn(
                    "Unsuffixed ML_KEM_PUBLIC_KEY / ML_KEM_PRIVATE_KEY env vars are set — IGNORED. " +
                        "Bind material under ML_KEM_*_CURRENT (for new wraps) or " +
                        "ML_KEM_*_LEGACY_V0 (for legacy unwrap-only) to opt the security " +
                        "service into reading them.",
                )
            }
            val service = MlKemCryptoKeyService.fromEnv()
            if (service != null) {
                val currentState = if (service.hasCurrentKek) "loaded" else "absent"
                val legacyState = if (service.hasLegacyKek) "loaded" else "absent"
                logger.info(
                    "CryptoKeyServicePort → MlKemCryptoKeyService (current=$currentState, legacy=$legacyState)",
                )
                service
            } else {
                logger.warn(
                    "CryptoKeyServicePort → NoOpCryptoKeyService — neither ML_KEM_*_CURRENT " +
                        "nor ML_KEM_*_LEGACY_V0 env-var pairs are set. Every /v1/dek/* call " +
                        "will throw IllegalStateException. Set at least one pair to enable crypto.",
                )
                NoOpCryptoKeyService
            }
        }

        single { GenerateDekUseCase(get(), get()) }
        single { WrapDekUseCase(get(), get()) }
        single { UnwrapDekUseCase(get(), get()) }
        single { RewrapDekUseCase(get(), get()) }
        single { GenerateNewKekPairUseCase(get(), get()) }
        single { GetKeyStatusUseCase(get(), get()) }

        // Admin allow-list — RFC 2253 subject DNs from SECURITY_ADMIN_SUBJECTS env var,
        // semicolon-separated (commas appear inside DNs). Empty set → every admin call
        // returns 403 + ADMIN_FORBIDDEN audit (fail-closed).
        single<AdminAllowList> {
            val raw = System.getenv("SECURITY_ADMIN_SUBJECTS").orEmpty()
            val subjects = raw.split(";").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            logger.info("AdminAllowList → StaticAdminAllowList(size=${subjects.size})")
            StaticAdminAllowList(subjects)
        }
    }

/**
 * Decides between the SLF4J fallback and the persistent HMAC-chained adapter based on
 * `SECURITY_DB_ENABLED`. Side-effects: starts a Hikari pool and runs Flyway migrations
 * when DB-backed mode is selected. Idempotent across startup retries.
 */
private fun buildAuditLogAdapter(): AuditLogPort {
    if (!SecurityDatabaseConfig.isEnabled()) {
        logger.warn(
            "DEV-ONLY: SECURITY_DB_ENABLED=false → binding Slf4jAuditLogAdapter (in-memory log " +
                "fallback). The tamper-evident HMAC-SHA-512 audit chain is DISABLED. This is " +
                "appropriate only for `./gradlew :infrastructure:run` smoke checks without MySQL. " +
                "Remove the env var (default is now `true`) for any non-trivial use.",
        )
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
