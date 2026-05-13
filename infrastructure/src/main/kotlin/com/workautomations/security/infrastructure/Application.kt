package com.workautomations.security.infrastructure

import com.workautomations.security.adapters.inbound.http.auth.PeerCertChainExtractor
import com.workautomations.security.adapters.inbound.http.auth.installMtlsAuth
import com.workautomations.security.adapters.inbound.http.installHealthRoute
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.infrastructure.config.RateLimitConfig
import com.workautomations.security.infrastructure.di.securityServiceModule
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import kotlinx.serialization.json.Json
import org.koin.ktor.ext.inject
import org.koin.ktor.plugin.Koin
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("com.workautomations.security.infrastructure.Application")

fun main() {
    val port = System.getenv("SECURITY_SERVICE_PORT")?.toIntOrNull() ?: DEFAULT_PORT
    val host = System.getenv("SECURITY_SERVICE_HOST") ?: DEFAULT_HOST
    logger.info(
        "Starting security-service on $host:$port (mTLS configured via PeerCertChainExtractor; " +
            "Netty SSL connector wiring lands in Stream E)",
    )
    embeddedServer(Netty, port = port, host = host, module = Application::securityModule).start(wait = true)
}

private const val DEFAULT_PORT = 8443
private const val DEFAULT_HOST = "0.0.0.0"

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
    logger.info(
        "Resolved RateLimitConfig: enabled={} capacity={} refillPerSec={} (env vars: {}, {}, {})",
        rateLimitConfig.enabled,
        rateLimitConfig.capacity,
        rateLimitConfig.refillTokensPerSecond,
        RateLimitConfig.ENV_ENABLED,
        RateLimitConfig.ENV_CAPACITY,
        RateLimitConfig.ENV_REFILL,
    )
    installMtlsAuth(extractor = extractor, auditLog = auditLog)

    routing {
        installHealthRoute()
    }
}
