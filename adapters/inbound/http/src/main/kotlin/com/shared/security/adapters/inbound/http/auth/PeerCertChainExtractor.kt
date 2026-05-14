package com.shared.security.adapters.inbound.http.auth

import io.ktor.server.application.ApplicationCall
import io.ktor.util.AttributeKey
import java.security.cert.X509Certificate

/**
 * Returns the verified peer certificate chain for the current call, or null when no
 * client certificate was presented or the chain was rejected by the TLS engine.
 *
 * Production: [NettySslPeerCertChainExtractor] reads the chain from the underlying Netty
 * SSL session (the JVM has already validated the chain against the truststore — by the time
 * a request reaches application code, an absent chain means "client did not present a
 * cert" and any non-null chain is trusted).
 *
 * Tests: [TestPeerCertChainExtractor] reads the chain from call attributes, allowing the
 * [MtlsAuthPlugin] to be unit-tested without a live TLS handshake.
 */
fun interface PeerCertChainExtractor {
    fun extract(call: ApplicationCall): Array<X509Certificate>?
}

/** Attribute key used by [TestPeerCertChainExtractor] to inject a synthetic chain. */
val TestPeerCertChainAttributeKey: AttributeKey<Array<X509Certificate>> =
    AttributeKey("security.test.peer-cert-chain")

/** Test-only extractor: reads the chain from a call attribute. */
class TestPeerCertChainExtractor : PeerCertChainExtractor {
    override fun extract(call: ApplicationCall): Array<X509Certificate>? =
        if (call.attributes.contains(TestPeerCertChainAttributeKey)) {
            call.attributes[TestPeerCertChainAttributeKey]
        } else {
            null
        }
}

/**
 * Fail-closed extractor: always returns null, causing every inbound call to be rejected
 * with HTTP 401 + `MTLS_REJECTED`. Use this when no real extractor is wired so misconfig
 * surfaces as 100% rejection rather than 100% acceptance. Never use in prod.
 */
class DenyAllPeerCertChainExtractor : PeerCertChainExtractor {
    override fun extract(call: ApplicationCall): Array<X509Certificate>? = null
}
