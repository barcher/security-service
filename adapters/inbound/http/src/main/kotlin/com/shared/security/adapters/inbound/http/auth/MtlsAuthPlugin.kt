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
 * 1. Calls [extractor] to fetch the verified peer cert chain. The TLS engine has already
 *    validated chain → CA → truststore by the time the context reaches application code, so
 *    presence of any non-null chain implies trust.
 * 2. If the chain is missing/empty: writes an `MTLS_REJECTED` audit event, returns HTTP 401,
 *    and contexts `finish()` so no downstream route handler runs.
 * 3. Otherwise: puts a [ClientPrincipal] (subject DN + SHA-256 fingerprint) into the context
 *    attributes for downstream routes to read via `context.clientPrincipal()`.
 *
 * Why an interceptor and not a sub-route auth provider: this gate must be unconditional —
 * every endpoint of the security service requires mTLS — and `intercept(Plugins)` runs
 * before routing, eliminating any chance of forgetting to wrap a route in `authenticate { }`.
 */
fun Application.installMtlsAuth(
    extractor: PeerCertChainExtractor,
    auditLog: AuditLogPort,
) {
    intercept(ApplicationCallPipeline.Plugins) {
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
