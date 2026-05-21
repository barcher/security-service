package com.shared.security.adapters.inbound.http.auth

import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.handler.codec.DecoderException
import org.slf4j.LoggerFactory
import javax.net.ssl.SSLHandshakeException

/**
 * Catches SSL handshake failures (including `Empty client certificate chain` when an
 * mTLS-required server rejects an anonymous client) and logs them concisely instead of
 * letting them surface as a full stack trace from Netty's default exception handler.
 *
 * **Why this matters:** the mTLS server intentionally rejects every connection that
 * doesn't present a cert chain trusted by the truststore — this is correct security
 * posture. But Netty's default behavior on an uncaught exception is `printStackTrace()`,
 * which floods the log on routine reconnaissance / health-prober traffic that doesn't
 * speak mTLS. We log a single INFO line (caller IP + cause message) and close the
 * channel cleanly.
 *
 * **Why an inbound handler and not a global `exceptionCaught` interceptor:** TLS
 * handshake errors fire BEFORE any request reaches application code, so there's no
 * `ApplicationCall` to hook into. Netty's pipeline-level `exceptionCaught` is the only
 * place to intercept.
 *
 * **Sharable:** stateless. One instance serves every accepted connection.
 */
@ChannelHandler.Sharable
class SslHandshakeExceptionHandler : ChannelInboundHandlerAdapter() {
    private val log = LoggerFactory.getLogger(SslHandshakeExceptionHandler::class.java)

    override fun exceptionCaught(
        ctx: ChannelHandlerContext,
        cause: Throwable,
    ) {
        val handshakeFailure = cause.findHandshakeException()
        if (handshakeFailure != null) {
            log.info(
                "mTLS handshake rejected: remote={} reason='{}'",
                ctx.channel().remoteAddress(),
                handshakeFailure.message,
            )
            ctx.close()
            return
        }
        ctx.fireExceptionCaught(cause)
    }

    /**
     * Netty often wraps the real handshake exception inside a `DecoderException`
     * (because the SSL layer is implemented as a `ByteToMessageDecoder`). Walk the
     * cause chain up to a small bound looking for the real `SSLHandshakeException`.
     */
    private fun Throwable.findHandshakeException(): SSLHandshakeException? {
        var current: Throwable? = this
        var hops = 0
        while (current != null && hops < MAX_CAUSE_HOPS) {
            if (current is SSLHandshakeException) return current
            if (current !is DecoderException && current.cause === current) return null
            current = current.cause
            hops++
        }
        return null
    }

    companion object {
        const val HANDLER_NAME = "ssl-handshake-exception"
        private const val MAX_CAUSE_HOPS = 8
    }
}
