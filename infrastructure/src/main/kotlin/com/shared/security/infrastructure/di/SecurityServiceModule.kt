package com.shared.security.infrastructure.di

import com.shared.security.adapters.inbound.http.auth.DenyAllPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.NettySslPeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.PeerCertChainExtractor
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.adapters.outbound.crypto.KekEnvelopeAdapter
import com.shared.security.adapters.outbound.crypto.MlKemCryptoKeyService
import com.shared.security.adapters.outbound.crypto.NoOpCryptoKeyService
import com.shared.security.adapters.outbound.jwtsigning.Es256JwtSigningKeyAdapter
import com.shared.security.adapters.outbound.persistence.ExposedJwtSigningKeyRepository
import com.shared.security.adapters.outbound.persistence.ExposedKekRepository
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.adapters.outbound.persistence.audit.AuditChainHasher
import com.shared.security.adapters.outbound.persistence.audit.AuditHmacKeyProvider
import com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
import com.shared.security.application.ports.AdminAllowList
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.JwtAudienceAllowList
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.KekEnvelopePort
import com.shared.security.application.ports.KekRepository
import com.shared.security.application.ports.StaticAdminAllowList
import com.shared.security.application.usecases.GenerateDekUseCase
import com.shared.security.application.usecases.GenerateNewKekPairUseCase
import com.shared.security.application.usecases.GetKeyStatusUseCase
import com.shared.security.application.usecases.RewrapDekUseCase
import com.shared.security.application.usecases.UnwrapDekUseCase
import com.shared.security.application.usecases.WrapDekUseCase
import com.shared.security.application.usecases.jwt.ActivateJwtSigningKeyUseCase
import com.shared.security.application.usecases.jwt.GenerateJwtSigningKeyPairUseCase
import com.shared.security.application.usecases.jwt.JwtSigningKeyPort
import com.shared.security.application.usecases.jwt.RunJwtSigningKeyHealthCheckUseCase
import com.shared.security.application.usecases.jwt.RunJwtSigningKeyPriorTtlUseCase
import com.shared.security.application.usecases.jwt.RunJwtSigningKeyRetentionUseCase
import com.shared.security.application.usecases.jwt.SignJwtUseCase
import com.shared.security.infrastructure.audit.Slf4jAuditLogAdapter
import com.shared.security.infrastructure.config.EnvJwtAudienceAllowList
import com.shared.security.infrastructure.config.RateLimitConfig
import com.shared.security.infrastructure.tls.MtlsConfig
import kotlinx.datetime.Clock
import org.koin.dsl.module
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours

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
        // SecurityDatabase is registered only when SECURITY_DB_ENABLED=true (or default).
        // JWT layer bindings call `getOrNull<SecurityDatabase>()` and fail loudly if absent.
        val sharedDb: SecurityDatabase? = provideSecurityDatabase()
        if (sharedDb != null) single<SecurityDatabase> { sharedDb }
        single<AuditLogPort> { buildAuditLogAdapter(sharedDb) }

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

        // Stream K K.0 — JWT signing-key layer. All three port bindings require the shared
        // SecurityDatabase; the JWT layer is unusable without it.
        single<KekRepository> {
            val db =
                requireNotNull(getOrNull<SecurityDatabase>()) {
                    "JWT signing-key layer requires SECURITY_DB_ENABLED=true (ExposedKekRepository needs the DB)"
                }
            ExposedKekRepository(db.database)
        }
        single<KekEnvelopePort> { KekEnvelopeAdapter(get<CryptoKeyServicePort>(), get<KekRepository>()) }
        single<JwtSigningKeyPort> { Es256JwtSigningKeyAdapter() }
        single<JwtSigningKeyRepository> {
            val db =
                requireNotNull(getOrNull<SecurityDatabase>()) {
                    "JWT signing-key layer requires SECURITY_DB_ENABLED=true"
                }
            ExposedJwtSigningKeyRepository(db.database)
        }
        single<JwtAudienceAllowList> {
            EnvJwtAudienceAllowList(System.getenv("SECURITY_JWT_AUDIENCE_ALLOWLIST"))
        }
        single { GenerateJwtSigningKeyPairUseCase(get(), get(), get(), get()) }
        single { ActivateJwtSigningKeyUseCase(get(), get()) }
        single { SignJwtUseCase(get(), get(), get(), get(), get()) }
        single { RunJwtSigningKeyHealthCheckUseCase(get(), get(), get(), get()) }
        single {
            RunJwtSigningKeyPriorTtlUseCase(
                repo = get(),
                auditLog = get(),
                ttl = JWT_PRIOR_TTL_HOURS.hours,
            )
        }
        single {
            RunJwtSigningKeyRetentionUseCase(
                repo = get(),
                auditLog = get(),
                retentionWindow = JWT_QUIESCED_RETENTION_HOURS.hours,
                retentionDays = JWT_RETIRED_RETENTION_DAYS,
            )
        }

        // Stream L L.0 — observability layer. Distinct allow-list from AdminAllowList;
        // distinct env var; same database. The observability use cases share the existing
        // audit-write port and add a dedicated read-side AuditLogQueryPort.
        single<com.shared.security.application.ports.DashboardObserverAllowList> {
            val raw = System.getenv("SECURITY_DASHBOARD_OBSERVER_SUBJECTS").orEmpty()
            val sep = if (raw.contains(';')) ";" else ","
            val subjects = raw.split(sep).map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            logger.info(
                "DashboardObserverAllowList → StaticDashboardObserverAllowList(size=${subjects.size})",
            )
            com.shared.security.application.ports.StaticDashboardObserverAllowList(subjects)
        }
        single<com.shared.security.application.ports.AuditLogQueryPort> {
            val db =
                requireNotNull(getOrNull<SecurityDatabase>()) {
                    "Observability surface requires SECURITY_DB_ENABLED=true"
                }
            com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogQueryRepository(db.database)
        }
        single { com.shared.security.application.usecases.observation.ListKeksObservationUseCase(get(), get()) }
        single { com.shared.security.application.usecases.observation.ListDeksObservationUseCase(get(), get()) }
        single {
            com.shared.security.application.usecases.observation.ListJwtSigningKeysObservationUseCase(get(), get())
        }
        single {
            com.shared.security.application.usecases.observation.SearchAuditEventsObservationUseCase(get(), get())
        }
        single {
            com.shared.security.application.usecases.observation.ListRecentRotationsObservationUseCase(get(), get())
        }

        // ── Stream C follow-up SHIP-01..02 — audit-shipper, retention, kek-backup wiring ───
        //
        // NoOp adapters until SHIP-03 + SHIP-04 land real R2/S3 implementations. The use cases
        // exercise the full path; only the bytes-leaving-the-process step is stubbed.
        single<com.shared.security.application.ports.ColdStoragePort> {
            com.shared.security.infrastructure.audit.NoOpColdStorageAdapter()
        }
        single<com.shared.security.application.ports.KekBackupVerifierPort> {
            com.shared.security.infrastructure.kek.NoOpKekBackupVerifier()
        }

        // Audit-shipped-checkpoint repo — backs both the shipper (last-shipped-id) and the
        // retention job (delete-bound). Requires SecurityDatabase.
        single {
            val db =
                requireNotNull(getOrNull<SecurityDatabase>()) {
                    "Audit shipper + retention require SECURITY_DB_ENABLED=true"
                }
            com.shared.security.adapters.outbound.persistence.audit.AuditShippedCheckpointRepository(db.database)
        }

        // RunKekHealthCheckUseCase — depends on CryptoKeyServicePort + AuditLogPort.
        single { com.shared.security.application.usecases.RunKekHealthCheckUseCase(get(), get()) }

        // RunKekPriorTtlUseCase — depends on KekRepository + DekRepository + AuditLogPort + Duration.
        single {
            com.shared.security.application.usecases.RunKekPriorTtlUseCase(
                kekRepository = get(),
                dekRepository = get(),
                auditLog = get(),
                quiesceWindow =
                    kotlin.time.Duration.parse(
                        System.getenv("SECURITY_KEK_QUIESCE_WINDOW") ?: "24h",
                    ),
            )
        }

        // DekRepository (needed by KekPriorTtl + DekRotation use cases).
        single<com.shared.security.application.ports.DekRepository> {
            val db =
                requireNotNull(getOrNull<SecurityDatabase>()) {
                    "DekRepository requires SECURITY_DB_ENABLED=true"
                }
            com.shared.security.adapters.outbound.persistence.ExposedDekRepository(db.database)
        }

        // RunDekRotationUseCase — depends on KekRepository + DekRepository + CryptoKeyServicePort
        // + activeKekPublicKey provider + AuditLogPort.
        single {
            com.shared.security.application.usecases.RunDekRotationUseCase(
                kekRepository = get(),
                dekRepository = get(),
                crypto = get(),
                activeKekPublicKey = {
                    // SHIP-02 placeholder. The DEK rotation use case needs the current active
                    // KEK's raw public-key bytes to call `rewrapDekForNewKek`. KekRecord stores
                    // only metadata (fingerprint, status, timestamps) and CryptoKeyServicePort
                    // exposes only `getPublicKeyFingerprint()`. A follow-up ticket adds
                    // `getActiveKekPublicKey(): ByteArray?` to CryptoKeyServicePort so the
                    // adapter (which holds the bytes in-process) can hand them out.
                    //
                    // Returning empty bytes here means DekRotationJob will fail gracefully —
                    // acceptable for the SHIP-02 wiring since SECURITY_SCHEDULER_ENABLED
                    // defaults to false; the operator turns the scheduler on only after the
                    // follow-up ticket wires this closure to a real provider.
                    ByteArray(0)
                },
                auditLog = get(),
            )
        }

        // RunAuditLogShipperUseCase — wires the closure-style deps to the
        // AuditShippedCheckpointRepository + ExposedAuditLogRepository.
        single {
            val auditLogRepo =
                get<AuditLogPort>() as
                    com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
            val checkpointRepo =
                get<com.shared.security.adapters.outbound.persistence.audit.AuditShippedCheckpointRepository>()
            val coldStorage = get<com.shared.security.application.ports.ColdStoragePort>()
            com.shared.security.application.usecases.RunAuditLogShipperUseCase(
                chainVerifier = { fromId, toId ->
                    when (val result = auditLogRepo.verifyChain(fromId, toId)) {
                        is com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
                            .VerifyResult.OK,
                        ->
                            com.shared.security.application.usecases.RunAuditLogShipperUseCase
                                .ChainVerification.Ok
                        is com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
                            .VerifyResult.EMPTY,
                        ->
                            com.shared.security.application.usecases.RunAuditLogShipperUseCase
                                .ChainVerification.Empty
                        is com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
                            .VerifyResult.BrokenAt,
                        ->
                            com.shared.security.application.usecases.RunAuditLogShipperUseCase
                                .ChainVerification.Broken(result.firstBadId)
                    }
                },
                batchReader = { fromId, toId ->
                    auditLogRepo.readShipBatch(fromId, toId, AUDIT_SHIP_BATCH_SIZE)
                        ?: com.shared.security.application.ports.AuditBatch(
                            batchId = "empty",
                            fromRowId = fromId,
                            toRowId = fromId,
                            bytesCanonical = ByteArray(0),
                        )
                },
                coldStorage = coldStorage,
                auditLog = get(),
                lastShippedIdProvider = { checkpointRepo.load() },
                lastShippedIdSaver = { value -> checkpointRepo.save(value) },
            )
        }

        // RunAuditRetentionUseCase — wires the deleter + last-shipped-id-provider closures
        // to the same backing stores. Retention duration honours FedRAMP AU-11 floor (7 years
        // = 2557 days) by default; operator can shorten via env var (loaded inline so the
        // env-read is visible).
        single {
            val auditLogRepo =
                get<AuditLogPort>() as
                    com.shared.security.adapters.outbound.persistence.audit.ExposedAuditLogRepository
            val checkpointRepo =
                get<com.shared.security.adapters.outbound.persistence.audit.AuditShippedCheckpointRepository>()
            val retentionDays =
                System.getenv("SECURITY_AUDIT_RETENTION_DAYS")?.toLongOrNull()
                    ?: DEFAULT_RETENTION_DAYS
            com.shared.security.application.usecases.RunAuditRetentionUseCase(
                deleter = { cutoff, maxId -> auditLogRepo.deleteOlderThan(cutoff, maxId) },
                lastShippedIdProvider = { checkpointRepo.load() },
                auditLog = get(),
                retentionDuration = kotlin.time.Duration.parse("${retentionDays}d"),
            )
        }

        // RunKekBackupVerifyUseCase — depends on KekBackupVerifierPort + AuditLogPort.
        single { com.shared.security.application.usecases.RunKekBackupVerifyUseCase(get(), get()) }

        // SchedulerConfig — env-driven; SECURITY_SCHEDULER_ENABLED gates the whole subsystem.
        single { com.shared.security.adapters.inbound.scheduler.SchedulerConfig.fromEnv() }

        // SecurityScheduler — composition of all 6 use cases. NOT started here — the
        // composition root (Application.kt) calls .start() after Koin boot completes.
        single {
            com.shared.security.adapters.inbound.scheduler.SecurityScheduler(
                config = get(),
                useCases =
                    com.shared.security.adapters.inbound.scheduler.SecurityScheduler.UseCases(
                        kekHealth = get(),
                        kekPriorTtl = get(),
                        dekRotation = get(),
                        auditShipper = get(),
                        auditRetention = get(),
                        kekBackupVerify = get(),
                    ),
            )
        }
    }

private const val AUDIT_SHIP_BATCH_SIZE: Int = 1000
private const val DEFAULT_RETENTION_DAYS: Long = 2557L // 7 years — FedRAMP AU-11 floor

private const val JWT_PRIOR_TTL_HOURS: Long = 24L
private const val JWT_QUIESCED_RETENTION_HOURS: Long = 24L
private const val JWT_RETIRED_RETENTION_DAYS: Long = 90L

/**
 * Build the shared [SecurityDatabase] instance once, or return null when DB-backed mode is
 * disabled. Runs Flyway migrations on first call. Used by both the audit log adapter and
 * the JWT signing-key layer; they share a single Hikari pool.
 */
private fun provideSecurityDatabase(): SecurityDatabase? {
    if (!SecurityDatabaseConfig.isEnabled()) return null
    val dbConfig = SecurityDatabaseConfig.fromEnv()
    val database = SecurityDatabase.create(dbConfig)
    SecurityFlywayMigrator(database.dataSource).migrate()
    return database
}

/**
 * Decides between the SLF4J fallback and the persistent HMAC-chained adapter based on
 * whether [provideSecurityDatabase] produced a database (i.e. `SECURITY_DB_ENABLED=true`).
 */
private fun buildAuditLogAdapter(database: SecurityDatabase?): AuditLogPort {
    if (database == null) {
        logger.warn(
            "DEV-ONLY: SECURITY_DB_ENABLED=false → binding Slf4jAuditLogAdapter (in-memory log " +
                "fallback). The tamper-evident HMAC-SHA-512 audit chain is DISABLED. This is " +
                "appropriate only for `./gradlew :infrastructure:run` smoke checks without MySQL. " +
                "Remove the env var (default is now `true`) for any non-trivial use.",
        )
        return Slf4jAuditLogAdapter()
    }
    val hmacKey = AuditHmacKeyProvider.fromEnv()
    val hasher = AuditChainHasher(hmacKey)
    logger.info("SECURITY_DB_ENABLED=true → binding ExposedAuditLogRepository with HMAC-SHA-512 chain")
    return ExposedAuditLogRepository(database.database, hasher)
}
