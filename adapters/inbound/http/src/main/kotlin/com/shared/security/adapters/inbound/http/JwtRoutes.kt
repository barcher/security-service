package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.auth.clientPrincipal
import com.shared.security.adapters.inbound.http.dto.ErrorResponse
import com.shared.security.adapters.inbound.http.dto.SignJwtRequestDto
import com.shared.security.adapters.inbound.http.dto.SignJwtResponseDto
import com.shared.security.application.usecases.jwt.SignJwtUseCase
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.post
import io.ktor.server.routing.route

/**
 * POST /v1/jwt/sign — Stream K K.0. Mints an ES256 JWT after enforcing the two-gate
 * caller-authentication contract (proposal §3.4a):
 *
 *   * Gate 1 — `MtlsAuthPlugin` runs ahead of this route and populates
 *     `call.clientPrincipal()`; a missing principal here means the request bypassed
 *     mTLS entirely (programming error) and is rejected 401.
 *   * Gate 2 — [SignJwtUseCase] consults [com.shared.security.application.ports.JwtAudienceAllowList];
 *     mismatched audiences return 403 with `audience_forbidden`.
 *
 * Missing ACTIVE signing key returns 503 with `no_active_key`; the route does not 500
 * because the calling service should retry once an operator activates a key. Sign
 * exceptions bubble up — they are bugs, not client errors.
 */
fun Routing.installJwtSignRoutes(signJwt: SignJwtUseCase) {
    route("/v1/jwt") {
        post("/sign") {
            val principal =
                call.clientPrincipal() ?: return@post call.respond(
                    HttpStatusCode.Unauthorized,
                    ErrorResponse("mtls_required"),
                )
            val req = call.receive<SignJwtRequestDto>()
            if (req.expiresInSeconds <= 0 || req.expiresInSeconds > MAX_TTL_SECONDS) {
                return@post call.respond(
                    HttpStatusCode.UnprocessableEntity,
                    ErrorResponse(
                        "malformed_request",
                        "expiresInSeconds must be between 1 and $MAX_TTL_SECONDS",
                    ),
                )
            }

            when (
                val result =
                    signJwt.execute(
                        SignJwtUseCase.Request(
                            subjectDn = principal.subjectDn,
                            subject = req.subject,
                            audience = req.audience,
                            issuer = req.issuer,
                            expiresInSeconds = req.expiresInSeconds,
                            extraClaims = req.extraClaims,
                        ),
                    )
            ) {
                is SignJwtUseCase.Result.Signed ->
                    call.respond(
                        HttpStatusCode.OK,
                        SignJwtResponseDto(
                            token = result.token,
                            kidHex = result.kid.joinToString("") { "%02x".format(it) },
                            expiresAt = result.expiresAt.epochSeconds,
                        ),
                    )

                SignJwtUseCase.Result.AudienceForbidden ->
                    call.respond(
                        HttpStatusCode.Forbidden,
                        ErrorResponse(
                            "audience_forbidden",
                            "subject DN is not allow-listed for the requested audience",
                        ),
                    )

                SignJwtUseCase.Result.NoActiveKey ->
                    call.respond(
                        HttpStatusCode.ServiceUnavailable,
                        ErrorResponse(
                            "no_active_key",
                            "no ACTIVE JWT signing key is configured; an operator must activate one",
                        ),
                    )
            }
        }
    }
}

// 24 hours; the proposal §5.1 cap. A request for a longer-lived token is a design error.
private const val MAX_TTL_SECONDS: Long = 86_400L
