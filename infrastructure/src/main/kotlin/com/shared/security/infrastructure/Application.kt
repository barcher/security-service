package com.shared.security.infrastructure

import com.shared.security.adapters.inbound.http.auth.PeerCertChainCaptureHandler
import com.shared.security.adapters.inbound.http.auth.PeerCertChainExtractor
import com.shared.security.adapters.inbound.http.auth.SslHandshakeExceptionHandler
import com.shared.security.adapters.inbound.http.auth.installMtlsAuth
import com.shared.security.adapters.inbound.http.installAdminRoutes
import com.shared.security.adapters.inbound.http.installBlindIndexRoutes
import com.shared.security.adapters.inbound.http.installCryptoRoutes
import com.shared.security.adapters.inbound.http.installHealthRoute
import com.shared.security.adapters.inbound.http.installJwksRoutes
import com.shared.security.adapters.inbound.http.installJwtSignRoutes
import com.shared.security.adapters.inbound.http.installObservabilityRoutes
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.application.ports.AdminAllowList
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.usecases.GenerateDekUseCase
import com.shared.security.application.usecases.GenerateNewKekPairUseCase
import com.shared.security.application.usecases.GetKeyStatusUseCase
import com.shared.security.application.usecases.RewrapDekUseCase
import com.shared.security.application.usecases.UnwrapDekUseCase
import com.shared.security.application.usecases.WrapDekUseCase
import com.shared.security.application.usecases.jwt.JwtSigningKeyPort
import com.shared.security.application.usecases.jwt.SignJwtUseCase
import com.shared.security.infrastructure.cli.GenerateKekCli
import com.shared.security.infrastructure.cli.ImportMonolithDeksCli
import com.shared.security.infrastructure.cli.JwtKeysCli
import com.shared.security.infrastructure.config.RateLimitConfig
import com.shared.security.infrastructure.di.securityServiceModule
import com.shared.security.infrastructure.tls.MtlsConfig
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopping
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import kotlinx.serialization.json.Json
import org.koin.ktor.ext.inject
import org.koin.ktor.plugin.Koin
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("com.shared.security.infrastructure.Application")

fun main(args: Array<String>) {
    // SKS-H11: load .env BEFORE any code reads System.getenv(). The dotenv loader walks
    // up from the working directory looking for `.env`, applies each KEY=VALUE into the
    // process environment, and treats existing System.getenv() values as authoritative
    // (so docker-compose / k8s env still wins over the file in deployed environments).
    // Replaces the temporary Gradle-layer loader that only worked when the service was
    // launched via `./gradlew :infrastructure:run` and broke every other launch path
    // (java -jar, IDE, debug, prod container).
    loadDotEnvIfPresent()
    when (args.firstOrNull()) {
        "generate-kek" -> {
            GenerateKekCli().run(args.drop(1))
            return
        }
        "import-monolith-deks" -> {
            ImportMonolithDeksCli().run(args.drop(1))
            return
        }
        "jwt-keys" -> {
            JwtKeysCli().run(args.drop(1))
            return
        }
        null, "" -> {
            // fall through to server start
        }
        else -> {
            System.err.println(
                "Unknown subcommand '${args[0]}'. Supported subcommands: generate-kek, " +
                    "import-monolith-deks, jwt-keys. Run with no arguments to start the HTTP server.",
            )
            kotlin.system.exitProcess(2)
        }
    }
    val port = System.getenv("SECURITY_SERVICE_PORT")?.toIntOrNull() ?: DEFAULT_PORT
    val publicPort =
        System.getenv("SECURITY_SERVICE_PUBLIC_PORT")?.toIntOrNull() ?: DEFAULT_PUBLIC_PORT
    val host = System.getenv("SECURITY_SERVICE_HOST") ?: DEFAULT_HOST
    buildServer(host = host, port = port, publicPort = publicPort).start(wait = true)
}

private const val DEFAULT_PORT = 8443
private const val DEFAULT_PUBLIC_PORT = 8442
private const val DEFAULT_HOST = "0.0.0.0"
private const val JWKS_RATE_LIMIT_CAPACITY = 60.0
private const val JWKS_RATE_LIMIT_REFILL_PER_SECOND = 10.0

/**
 * Load `.env` from the working directory (or any parent) and apply each entry into the
 * process environment. Existing `System.getenv()` values take priority — the file fills
 * gaps, never overrides. Silent no-op when no `.env` is found (CI, containerised prod).
 */
private fun loadDotEnvIfPresent() {
    val dotenv =
        io.github.cdimascio.dotenv.dotenv {
            ignoreIfMissing = true
            ignoreIfMalformed = true
        }
    var applied = 0
    dotenv.entries().forEach { entry ->
        if (System.getenv(entry.key) == null) {
            // The dotenv lib parses values for us. Apply via the JVM env-map reflection
            // dance that's the standard workaround for the fact that JDK `System.getenv()`
            // returns an unmodifiable map.
            setEnvVar(entry.key, entry.value)
            applied++
        }
    }
    if (applied > 0) {
        logger.info("loadDotEnvIfPresent: applied {} entries from .env (process env wins on collisions)", applied)
    } else {
        logger.warn(
            "loadDotEnvIfPresent: ZERO entries from .env (CWD={}). Expected: <project-root>/.env. " +
                "If you're not in production with OS-level env, your .env file is not being found.",
            System.getProperty("user.dir"),
        )
    }
}

/**
 * Mutate the JVM's process-environment map. The map returned by `System.getenv()` is
 * unmodifiable, so we reach into its backing field. This is the same trick the JDK
 * itself uses in `ProcessEnvironment.toEnvironmentBlock`; it's stable on HotSpot 8+.
 */
@Suppress("UNCHECKED_CAST")
private fun setEnvVar(
    key: String,
    value: String,
) {
    try {
        val env = System.getenv()
        val field = env.javaClass.getDeclaredField("m")
        field.isAccessible = true
        (field.get(env) as MutableMap<String, String>)[key] = value
    } catch (e: java.lang.reflect.InaccessibleObjectException) {
        logger.warn(
            "loadDotEnvIfPresent: cannot inject .env values into process env on this JDK. " +
                "Required JVM flag missing: --add-opens java.base/java.util=ALL-UNNAMED. " +
                "Set via -D or add to applicationDefaultJvmArgs. Values from .env will be IGNORED.",
        )
    } catch (e: ReflectiveOperationException) {
        logger.warn("loadDotEnvIfPresent: could not inject {} into process env: {}", key, e.message)
    }
}

/**
 * Build the embedded Netty server with **two TLS connectors**:
 *
 * 1. **mTLS lane** on [port] (default 8443) — `sslConnector` with both the server keystore
 *    AND the CA truststore. Ktor's `NettyChannelInitializer` sees `hasTrustStore == true`
 *    and unconditionally calls `engine.setNeedClientAuth(true)`, so anonymous handshakes
 *    are rejected at the TLS layer with alert `certificate_required`. Carries every
 *    mTLS-required route under /v1/dek, /v1/admin, /v1/observability, plus /v1/jwt/sign.
 *
 * 2. **Public lane** on [publicPort] (default 8442) — `sslConnector` with the same keystore
 *    but **no truststore**. Without a truststore Ktor does NOT call `setNeedClientAuth`,
 *    so the engine never requests a client cert and anonymous handshakes succeed. This
 *    lane carries the two genuinely public routes — `GET /v1/jwks` (RFC 7517 public key
 *    material) and `GET /v1/health` (k8s probe). Both are still gated at the application
 *    layer by `MtlsAuthPlugin`'s `publicPathPrefixes` allow-list, so a caller that
 *    accidentally hits a non-public route on this port receives HTTP 401 + `MTLS_REJECTED`.
 *
 * Why two connectors instead of a single `wantClientAuth` connector: Ktor 3.1.1's
 * `NettyApplicationEngine` defers `channelPipelineConfig` (our hook for replacing the
 * SslHandler) to **after** ALPN negotiation completes — which happens as part of the TLS
 * handshake. By the time our hook runs, the handshake has already failed for anonymous
 * clients. Splitting connectors avoids the timing problem entirely: each Ktor SslHandler
 * is correctly configured at construction by virtue of the connector's truststore
 * presence/absence.
 *
 * The [NettySslPeerCertChainExtractor] (wired in `SecurityServiceModule`) pulls the
 * validated chain from whichever connector's `SslHandler` saw the connection. On the
 * public lane no chain is ever present, so the extractor returns empty and
 * `MtlsAuthPlugin` enforces the allow-list.
 *
 * **Plaintext fallback (DEV ONLY):** when `MtlsConfig.fromEnv()` returns null (any
 * required env var unset), the server falls back to plaintext on [port] and logs a loud
 * `DEV-ONLY` warning. In this mode the `DenyAllPeerCertChainExtractor` is bound, so
 * every authenticated endpoint returns 401 — the service literally cannot serve real
 * traffic without TLS. The public connector is NOT bound in this mode (no point — there
 * is no TLS material to terminate). **NEVER use the plaintext fallback in any deployed
 * environment.** The Phase-14 boundary rules forbid it.
 */
internal fun buildServer(
    host: String,
    port: Int,
    publicPort: Int,
): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
    val mtls = MtlsConfig.fromEnv()
    if (mtls == null) {
        logger.warn(
            "DEV-ONLY: starting security-service on $host:$port WITHOUT mTLS — MtlsConfig env " +
                "vars are unset (SECURITY_SERVICE_KEYSTORE_PATH and friends). Every authenticated " +
                "endpoint will return 401. Set the keystore/truststore env vars before any " +
                "non-trivial use.",
        )
        return embeddedServer(
            factory = Netty,
            environment =
                applicationEnvironment {
                    log = org.slf4j.LoggerFactory.getLogger("io.ktor.server.application")
                },
            configure = {
                connector {
                    this.host = host
                    this.port = port
                }
            },
            module = { securityModule() },
        )
    }
    val keyStore = mtls.loadKeyStore()
    val trustStore = mtls.loadTrustStore()
    logger.info(
        "Starting security-service on $host:$port with mTLS " +
            "(keystore=${mtls.keyStorePath}, truststore=${mtls.trustStorePath}, alias=${mtls.keyStoreAlias})",
    )
    val captureHandler = PeerCertChainCaptureHandler()
    val handshakeExceptionHandler = SslHandshakeExceptionHandler()
    logger.info(
        "TLS posture: two connectors. mTLS-REQUIRE on $port (truststore configured -> Ktor " +
            "sets needClientAuth=true). Public on $publicPort (no truststore configured -> " +
            "anonymous handshakes accepted). MtlsAuthPlugin allow-lists /v1/jwks + /v1/health " +
            "at the app layer so they work on either port; every other route returns 401 on " +
            "the public port. Patch=2026-05-26-two-connectors.",
    )
    return embeddedServer(
        factory = Netty,
        environment =
            applicationEnvironment {
                log = org.slf4j.LoggerFactory.getLogger("io.ktor.server.application")
            },
        configure = {
            // The keystore-password CharArray is zeroized by Ktor's NettyChannelInitializer
            // after each connector consumes it. Return a fresh copy per call so the second
            // connector doesn't see an emptied buffer.
            val freshPassword: () -> CharArray = { mtls.keyStorePassword.copyOf() }
            // mTLS lane — truststore set => Ktor sets needClientAuth(true) on the engine.
            sslConnector(
                keyStore = keyStore,
                keyAlias = mtls.keyStoreAlias,
                keyStorePassword = freshPassword,
                privateKeyPassword = freshPassword,
            ) {
                this.host = host
                this.port = port
                this.trustStore = trustStore
            }
            // Public lane — same keystore, NO truststore. Without a truststore Ktor never
            // calls setNeedClientAuth(true), so anonymous handshakes succeed. The two
            // documented public routes (`/v1/jwks`, `/v1/health`) are reachable here;
            // every other route is 401'd at the app layer by MtlsAuthPlugin's allow-list.
            sslConnector(
                keyStore = keyStore,
                keyAlias = mtls.keyStoreAlias,
                keyStorePassword = freshPassword,
                privateKeyPassword = freshPassword,
            ) {
                this.host = host
                this.port = publicPort
                // intentionally no trustStore = ...
            }
            // SKS-E07b: install the peer-cert-chain capture handler in every accepted
            // connection's pipeline. On `SslHandshakeCompletionEvent.SUCCESS`, it copies
            // the validated chain from `SslHandler.engine().session.peerCertificates`
            // into a Netty `AttributeKey` on the channel — so the auth interceptor reads
            // O(1) instead of touching the SSL session on every request.
            channelPipelineConfig = {
                addLast(PeerCertChainCaptureHandler.HANDLER_NAME, captureHandler)
                // Catches SSL handshake failures (untrusted client cert against the
                // mTLS-required connector) and logs them as a single INFO line rather
                // than letting Netty's default handler dump a full stack trace.
                addLast(SslHandshakeExceptionHandler.HANDLER_NAME, handshakeExceptionHandler)
            }
        },
        module = { securityModule() },
    )
}

fun Application.securityModule() {
    install(Koin) {
        modules(securityServiceModule)
    }
    install(ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
    install(CallLogging)

    val extractor by inject<PeerCertChainExtractor>()
    val auditLog by inject<AuditLogPort>()
    val rateLimitConfig by inject<RateLimitConfig>()
    val rateLimiter by inject<PerSubjectRateLimiter>()
    val generateDek by inject<GenerateDekUseCase>()
    val wrapDek by inject<WrapDekUseCase>()
    val unwrapDek by inject<UnwrapDekUseCase>()
    val rewrapDek by inject<RewrapDekUseCase>()
    val generateNewKekPair by inject<GenerateNewKekPairUseCase>()
    val getKeyStatus by inject<GetKeyStatusUseCase>()
    val adminAllowList by inject<AdminAllowList>()
    val signJwt by inject<SignJwtUseCase>()
    val computeEmailBlindIndex by
        inject<com.shared.security.application.usecases.blindindex.ComputeEmailBlindIndexUseCase>()
    val jwtSigningKeyRepo by inject<JwtSigningKeyRepository>()
    val jwtSigningPort by inject<JwtSigningKeyPort>()
    val observerAllowList by inject<com.shared.security.application.ports.DashboardObserverAllowList>()
    val listKeksObservation by
        inject<com.shared.security.application.usecases.observation.ListKeksObservationUseCase>()
    val listDeksObservation by
        inject<com.shared.security.application.usecases.observation.ListDeksObservationUseCase>()
    val listJwtKeysObservation by
        inject<com.shared.security.application.usecases.observation.ListJwtSigningKeysObservationUseCase>()
    val searchAuditObservation by
        inject<com.shared.security.application.usecases.observation.SearchAuditEventsObservationUseCase>()
    val listRecentRotationsObservation by
        inject<com.shared.security.application.usecases.observation.ListRecentRotationsObservationUseCase>()
    logger.info(
        "Resolved RateLimitConfig: enabled={} capacity={} refillPerSec={} (env vars: {}, {}, {})",
        rateLimitConfig.enabled,
        rateLimitConfig.capacity,
        rateLimitConfig.refillTokensPerSecond,
        RateLimitConfig.ENV_ENABLED,
        RateLimitConfig.ENV_CAPACITY,
        RateLimitConfig.ENV_REFILL,
    )
    installMtlsAuth(
        extractor = extractor,
        auditLog = auditLog,
        publicPathPrefixes = setOf("/v1/jwks", "/v1/health"),
    )

    // Stream C follow-up SHIP-02 — start the SecurityScheduler. The .start() call is a
    // no-op when SECURITY_SCHEDULER_ENABLED=false (the default for safety — operator opts
    // in once SHIP-03/SHIP-04 wire real cold-storage + backup-verify adapters). The
    // .stop() call is registered on ApplicationStopping so graceful shutdown waits for
    // in-flight jobs (Quartz `shutdown(true)`).
    val securityScheduler by inject<com.shared.security.adapters.inbound.scheduler.SecurityScheduler>()
    securityScheduler.start()
    monitor.subscribe(ApplicationStopping) {
        runCatching { securityScheduler.stop() }
            .onFailure { logger.warn("SecurityScheduler.stop() failed during shutdown", it) }
    }

    routing {
        installHealthRoute()
        installCryptoRoutes(
            generateDek = generateDek,
            wrapDek = wrapDek,
            unwrapDek = unwrapDek,
            rewrapDek = rewrapDek,
            unwrapRateLimiter = if (rateLimitConfig.enabled) rateLimiter else null,
            auditLog = auditLog,
        )
        installAdminRoutes(
            adminAllowList = adminAllowList,
            auditLog = auditLog,
            generateNewKekPair = generateNewKekPair,
            getKeyStatus = getKeyStatus,
        )
        installJwtSignRoutes(signJwt = signJwt)
        installBlindIndexRoutes(computeEmailBlindIndex = computeEmailBlindIndex)
        // JWKS is unauthenticated; rate-limit per-IP to prevent abuse. Consumers cache the
        // JWKS for 5 minutes and only refetch on `kid` miss, so a generous per-IP cap is
        // safe. Hardcoded here (not env-tunable yet) — promote to RateLimitConfig if/when
        // operators ask for it.
        installJwksRoutes(
            repo = jwtSigningKeyRepo,
            signing = jwtSigningPort,
            rateLimiter =
                com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter(
                    capacity = JWKS_RATE_LIMIT_CAPACITY,
                    refillTokensPerSecond = JWKS_RATE_LIMIT_REFILL_PER_SECOND,
                ),
        )
        installObservabilityRoutes(
            observerAllowList = observerAllowList,
            auditLog = auditLog,
            rateLimiter = if (rateLimitConfig.enabled) rateLimiter else null,
            listKeks = listKeksObservation,
            listDeks = listDeksObservation,
            listJwtSigningKeys = listJwtKeysObservation,
            searchAuditEvents = searchAuditObservation,
            listRecentRotations = listRecentRotationsObservation,
        )
    }
}
