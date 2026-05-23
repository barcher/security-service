package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.dto.JwkDto
import com.shared.security.adapters.inbound.http.dto.JwksResponseDto
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.usecases.jwt.JwtSigningKeyPort
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
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
 * No mTLS gate on this route: JWKS is intentionally public so JWT verification can be
 * a pure-CPU operation in any consumer.
 */
fun Routing.installJwksRoutes(
    repo: JwtSigningKeyRepository,
    signing: JwtSigningKeyPort,
) {
    route("/v1") {
        get("/jwks") {
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
