package com.shared.security.adapters.inbound.http.auth

import com.shared.security.adapters.inbound.http.auth.PeerCertChainCaptureHandler.Companion.PEER_CERT_CHAIN_KEY
import io.ktor.server.application.ApplicationCall
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate

/**
 * Production [PeerCertChainExtractor]: reads the validated peer certificate chain from
 * a Netty channel [io.netty.util.AttributeKey] that [PeerCertChainCaptureHandler]
 * populates once at SSL handshake completion.
 *
 * **Invariant:** when this extractor returns a non-null chain, it is *trusted* — Netty's
 * `SslHandler` (configured with `needClientAuth = true` against the truststore) has
 * already validated the chain against the CA before any request reaches application
 * code. Null means either the client did not present a cert, the call is not over a
 * Netty/TLS channel, or the capture handler is not installed in the pipeline.
 *
 * **Hot path is O(1):** every extraction reads a single Netty `AttributeKey`. The
 * cert chain capture is a one-time post-handshake event, not a per-request operation.
 *
 * **Remaining bridge — `tryGetNettyChannel`:** to read the channel's attribute, we need
 * the channel. Ktor 3.x does not expose the Netty channel publicly on `ApplicationCall`,
 * so we reach it via reflection over the call class's `ChannelHandlerContext` field. The
 * lookup filters by VALUE-type (not field name), so it survives Ktor renaming the
 * property between minor versions. This is the only Ktor-internals coupling that
 * remains; tracked for elimination when Ktor exposes a public `engineCall` API or we
 * move to a different engine.
 */
class NettySslPeerCertChainExtractor : PeerCertChainExtractor {
    private val log = LoggerFactory.getLogger(NettySslPeerCertChainExtractor::class.java)

    override fun extract(call: ApplicationCall): Array<X509Certificate>? {
        val channel = call.tryGetNettyChannel()
        if (channel == null) {
            log.debug("extract: no Netty channel resolvable from call class={}", call::class.java.name)
            return null
        }
        return readChainFromChannelOrAncestors(channel)
    }

    /**
     * Walk from this channel up the parent chain reading [PEER_CERT_CHAIN_KEY]. Required
     * for HTTP/2: the capture handler runs on the parent (connection-level) channel where
     * the TLS handshake completed. Child channels (one per HTTP/2 stream) inherit nothing
     * but they can reach the parent via `Channel.parent()`. For HTTP/1.1, the parent walk
     * terminates after one step (the attribute is on the same channel as the request).
     */
    private fun readChainFromChannelOrAncestors(start: Channel): Array<X509Certificate>? {
        var current: Channel? = start
        while (current != null) {
            val chain = current.attr(PEER_CERT_CHAIN_KEY).get()
            if (chain != null && chain.isNotEmpty()) return chain
            current = current.parent()
        }
        log.debug(
            "extract: no peer-cert-chain attribute on channel or any ancestor; pipeline=[{}]",
            start.pipeline().names().joinToString(),
        )
        return null
    }

    private fun ApplicationCall.tryGetNettyChannel(): Channel? {
        var clazz: Class<*>? = this::class.java
        while (clazz != null && clazz != Any::class.java) {
            val channel = readChannelFromClassFields(this, clazz)
            if (channel != null) return channel
            clazz = clazz.superclass
        }
        return null
    }

    private fun readChannelFromClassFields(
        instance: Any,
        clazz: Class<*>,
    ): Channel? =
        clazz.declaredFields
            .asSequence()
            .filter { ChannelHandlerContext::class.java.isAssignableFrom(it.type) }
            .mapNotNull { readChannelHandlerContext(instance, it) }
            .firstOrNull()
            ?.channel()

    private fun readChannelHandlerContext(
        instance: Any,
        field: java.lang.reflect.Field,
    ): ChannelHandlerContext? =
        try {
            field.isAccessible = true
            field.get(instance) as? ChannelHandlerContext
        } catch (e: ReflectiveOperationException) {
            log.debug("extract: reflection on {} threw", field, e)
            null
        } catch (e: SecurityException) {
            log.debug("extract: SecurityManager blocked {}", field, e)
            null
        }
}
