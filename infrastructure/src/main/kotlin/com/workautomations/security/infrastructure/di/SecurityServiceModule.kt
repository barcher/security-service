package com.workautomations.security.infrastructure.di

import com.workautomations.security.adapters.inbound.http.auth.DenyAllPeerCertChainExtractor
import com.workautomations.security.adapters.inbound.http.auth.PeerCertChainExtractor
import com.workautomations.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.infrastructure.audit.Slf4jAuditLogAdapter
import com.workautomations.security.infrastructure.config.RateLimitConfig
import kotlinx.datetime.Clock
import org.koin.dsl.module

/**
 * Composition root for the security service.
 *
 * Stream A wired only `/v1/health`. Stream B adds:
 *
 * - [PeerCertChainExtractor]: bound to [DenyAllPeerCertChainExtractor] — every call is
 *   rejected until Stream E swaps this binding for the real Netty/sidecar-header extractor.
 *   This is intentional fail-closed wiring: we'd rather every endpoint return 401 than
 *   silently accept unauthenticated traffic.
 * - [AuditLogPort]: bound to [Slf4jAuditLogAdapter] — events go to slf4j INFO. The
 *   persistent `ExposedAuditLogRepository` (with HMAC-SHA-512 chain) replaces this in
 *   Stream C (SKS-C04 + SKS-C05). The port signature does not change across that swap.
 * - [RateLimitConfig] + [PerSubjectRateLimiter]: limiter is always constructed but the route
 *   layer (see Application.kt) only wires it into `/v1/dek/unwrap` when
 *   [RateLimitConfig.enabled] is true. Configuration is read from env vars at startup —
 *   see [RateLimitConfig] KDoc for the full env-var list and operator notes.
 *
 * Stream C will add persistence + Quartz job bindings here.
 */
val securityServiceModule =
    module {
        single<AuditLogPort> { Slf4jAuditLogAdapter() }
        single<PeerCertChainExtractor> { DenyAllPeerCertChainExtractor() }
        single { RateLimitConfig.fromEnv() }
        single {
            val config = get<RateLimitConfig>()
            // When disabled, build a sentinel limiter that is never consulted by the route
            // layer; capacity / refill are not validated against zero in that case.
            val capacity = if (config.enabled) config.capacity else 1.0
            val refill = if (config.enabled) config.refillTokensPerSecond else 1.0
            PerSubjectRateLimiter(capacity = capacity, refillTokensPerSecond = refill, clock = Clock.System)
        }
    }
