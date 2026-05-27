package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.dto.JwkDto
import com.shared.security.adapters.inbound.http.dto.JwksResponseDto
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.usecases.jwt.JwtSigningKeyPort
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.origin
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import io.ktor.server.routing.route

/**
 * GET /v1/jwks — Stream K K.0. RFC 7517 JSON Web Key Set listing of every key currently
 * publishable (ACTIVE + PRIOR — i.e. anything a consumer may still need to verify a token
 * against during a rotation window). QUIESCED and RETIRED keys are NOT published.
 *
 * Cache-Control per K-amend-7 open-question decision: `public, max-age=300` (5 min).
 * Consumers (the shared client's `LocalJwksVerifierAdapter`) refresh hourly on the
 * normal path AND eagerly on a `kid` cache-miss, so a 5 min upstream cache window is the
 * right balance between propagation latency for newly-staged keys and load on the JWKS
 * endpoint.
 *
 * **Public route.** This endpoint is reachable without a client certificate — it is on the
 * `publicPathPrefixes` allow-list passed to `installMtlsAuth` in `Application.kt`. The
 * TLS connector uses `wantClientAuth = true` so anonymous handshakes succeed for this path.
 *
 * **Rate limiting.** Because callers are anonymous (no subject DN), the optional [rateLimiter]
 * is keyed by [io.ktor.server.plugins.origin] remoteHost (the client IP as Ktor sees it,
 * respecting `X-Forwarded-For` when the `ForwardedHeaders` plugin is installed). Operators
 * should configure modest per-IP limits — consumers cache the JWKS for 5 minutes and only
 * refetch on `kid` miss, so legitimate request rates are very low. When [rateLimiter] is
 * `null` the route is unrestricted (sensible only when an upstream layer enforces limits).
 * An over-cap caller receives HTTP 429.
 */
fun Routing.installJwksRoutes(
    repo: JwtSigningKeyRepository,
    signing: JwtSigningKeyPort,
    rateLimiter: PerSubjectRateLimiter? = null,
) {
    route("/v1") {
        get("/jwks") {
            if (rateLimiter != null) {
                val remote = call.request.origin.remoteHost
                if (!rateLimiter.tryConsume(remote)) {
                    call.respond(HttpStatusCode.TooManyRequests, mapOf("error" to "rate_limit_exceeded"))
                    return@get
                }
            }
            val keys =
                repo.findAllPublishable().map { rec ->
                    val coords = signing.spkiToJwkXY(rec.publicKeySpki)
                    JwkDto(
                        x = coords.x,
                        y = coords.y,
                        kid = rec.kid.joinToString("") { "%02x".format(it) },
                    )
                }
            call.response.header(HttpHeaders.CacheControl, "public, max-age=$CACHE_MAX_AGE_SECONDS")
            call.respond(HttpStatusCode.OK, JwksResponseDto(keys = keys))
        }
    }
}

private const val CACHE_MAX_AGE_SECONDS: Long = 300L
