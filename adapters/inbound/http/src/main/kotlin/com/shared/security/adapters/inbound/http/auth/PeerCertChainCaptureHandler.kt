package com.shared.security.adapters.inbound.http.auth

import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.handler.ssl.SslHandler
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import io.netty.util.AttributeKey
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate

/**
 * Captures the validated peer certificate chain from the Netty `SslHandler`'s session
 * into a channel [AttributeKey] **once**, at SSL handshake completion. Downstream
 * application code reads from `channel.attr(PEER_CERT_CHAIN_KEY).get()` in O(1) rather
 * than re-reading the SSL session on every request.
 *
 * **Pipeline placement:** install AFTER `SslHandler` so the handshake-completion event
 * has already been consumed by `SslHandler` (which validates the chain against the
 * truststore). The event re-fires up the pipeline so we see it here.
 *
 * **Sharable:** this handler holds no state; the cert chain is stored on the channel,
 * not on the handler. Marked [ChannelHandler.Sharable] so one instance can serve every
 * accepted connection.
 *
 * **HTTP/2 note:** the SSL handshake happens on the parent (connection-level) channel.
 * For HTTP/2, child channels (one per stream) don't have their own `SslHandler`. The
 * AttributeKey is set on the parent; per-stream code reads from `channel.parent().attr(KEY)`.
 */
@ChannelHandler.Sharable
class PeerCertChainCaptureHandler : ChannelInboundHandlerAdapter() {
    private val log = LoggerFactory.getLogger(PeerCertChainCaptureHandler::class.java)

    override fun userEventTriggered(
        ctx: ChannelHandlerContext,
        evt: Any,
    ) {
        if (evt is SslHandshakeCompletionEvent && evt.isSuccess) {
            captureChain(ctx)
        }
        ctx.fireUserEventTriggered(evt)
    }

    private fun captureChain(ctx: ChannelHandlerContext) {
        val sslHandler = ctx.pipeline().get(SslHandler::class.java)
        if (sslHandler == null) {
            log.debug("captureChain: SslHandler missing at handshake completion; skipping capture")
            return
        }
        val chain =
            runCatching {
                sslHandler.engine().session.peerCertificates
                    .filterIsInstance<X509Certificate>()
                    .toTypedArray()
                    .takeIf { it.isNotEmpty() }
            }.getOrNull()
        if (chain != null) {
            ctx.channel().attr(PEER_CERT_CHAIN_KEY).set(chain)
            log.debug("captureChain: stored {} cert(s) on channel {}", chain.size, ctx.channel())
        } else {
            log.debug("captureChain: handshake completed but no peer certs; skipping capture")
        }
    }

    companion object {
        /** Channel attribute holding the validated peer cert chain, populated once per handshake. */
        val PEER_CERT_CHAIN_KEY: AttributeKey<Array<X509Certificate>> =
            AttributeKey.valueOf<Array<X509Certificate>>("security.peer-cert-chain")

        const val HANDLER_NAME = "peer-cert-chain-capture"
    }
}
