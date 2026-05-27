package com.shared.security.adapters.inbound.http.auth

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import kotlinx.datetime.Clock
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * Installs the mTLS authentication interceptor.
 *
 * The interceptor runs in the `Plugins` phase of every context. It:
 * 1. If the request URI exactly matches a prefix in [publicPathPrefixes] (or is `<prefix>/…`
 *    or `<prefix>?…`), skips the cert check entirely. Used for the two genuinely-public
 *    routes: `GET /v1/jwks` (RFC 7517 public key material; required for any consumer
 *    service to verify ES256 tokens) and `GET /v1/health` (k8s liveness/readiness probe).
 *    The match is prefix-only — `/v1/jwks-other` would NOT match `/v1/jwks`.
 * 2. Calls [extractor] to fetch the verified peer cert chain. The TLS engine has already
 *    validated chain → CA → truststore by the time the context reaches application code
 *    (the Netty `sslConnector` is configured with `wantClientAuth = true`; presented certs
 *    are validated against the truststore and rejected at handshake if they don't chain).
 * 3. If the chain is missing/empty: writes an `MTLS_REJECTED` audit event, returns HTTP 401,
 *    and contexts `finish()` so no downstream route handler runs.
 * 4. Otherwise: puts a [ClientPrincipal] (subject DN + SHA-256 fingerprint) into the context
 *    attributes for downstream routes to read via `context.clientPrincipal()`.
 *
 * Why an interceptor and not a sub-route auth provider: this gate sits ahead of all routing
 * so a new endpoint that forgets to wrap itself in `authenticate { }` is still cert-gated
 * by default. Adding a route to [publicPathPrefixes] is an explicit, reviewable opt-out —
 * keep that set as narrow as the architecture allows (currently two paths).
 *
 * **Pair this with the connector topology.** `Application.kt::buildServer` exposes TWO
 * TLS connectors: an mTLS-required one on `SECURITY_SERVICE_PORT` (Ktor sets
 * `needClientAuth=true` because that connector has a truststore), and a public one on
 * `SECURITY_SERVICE_PUBLIC_PORT` with no truststore — anonymous handshakes succeed there.
 * Routes are global across both connectors; this allow-list is the application-layer
 * filter that decides which routes are reachable when the caller presents no cert. If a
 * new public route is added at the routing layer without being added here, the route is
 * still 401-gated on the public port — fail-closed by default.
 */
fun Application.installMtlsAuth(
    extractor: PeerCertChainExtractor,
    auditLog: AuditLogPort,
    publicPathPrefixes: Set<String> = emptySet(),
) {
    intercept(ApplicationCallPipeline.Plugins) {
        val uri = context.request.uri
        if (publicPathPrefixes.any { uri == it || uri.startsWith("$it/") || uri.startsWith("$it?") }) {
            return@intercept
        }
        val chain = extractor.extract(context)
        if (chain == null || chain.isEmpty()) {
            auditLog.write(
                AuditEvent(
                    occurredAt = Clock.System.now(),
                    eventType = AuditEventType.MTLS_REJECTED,
                    actorSubject = null,
                    success = false,
                    detailJson = """{"reason":"no_client_certificate","path":"${context.request.uri}"}""",
                ),
            )
            context.respond(HttpStatusCode.Unauthorized, mapOf("error" to "mtls_required"))
            finish()
            return@intercept
        }
        context.attributes.put(ClientPrincipalKey, chain.first().toClientPrincipal())
    }
}

private fun X509Certificate.toClientPrincipal(): ClientPrincipal {
    val subjectDn = subjectX500Principal.name
    val digest = MessageDigest.getInstance("SHA-256").digest(encoded)
    val fingerprint = digest.joinToString(":") { "%02x".format(it) }
    return ClientPrincipal(subjectDn = subjectDn, certFingerprint = fingerprint)
}
