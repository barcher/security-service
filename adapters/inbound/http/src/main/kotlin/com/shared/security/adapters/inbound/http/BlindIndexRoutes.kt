package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.dto.EmailBlindIndexRequest
import com.shared.security.adapters.inbound.http.dto.EmailBlindIndexResponse
import com.shared.security.adapters.inbound.http.dto.ErrorResponse
import com.shared.security.application.usecases.blindindex.ComputeEmailBlindIndexUseCase
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import java.util.Base64

/**
 * Email blind-index route. Runs only after [MtlsAuthPlugin] has authenticated the caller
 * over the operational lane (the monolith). Computes a one-way 16-byte HMAC over the
 * normalized email and returns it; the HMAC key never leaves the security service.
 *
 * Deliberately writes NO audit row per call (routine, high-volume, one-way) and NEVER logs
 * the plaintext email — enforced by ArchUnit S-22 (no `email` identifier reaches a logger
 * in this file).
 */
fun Routing.installBlindIndexRoutes(computeEmailBlindIndex: ComputeEmailBlindIndexUseCase) {
    val b64Encoder = Base64.getEncoder()

    route("/v1/blind-index") {
        post("/email") {
            val request = call.receive<EmailBlindIndexRequest>()
            if (request.email.isBlank()) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("email_required"))
                return@post
            }
            val hash = computeEmailBlindIndex.compute(request.email)
            call.respond(
                HttpStatusCode.OK,
                EmailBlindIndexResponse(blindIndexB64 = b64Encoder.encodeToString(hash)),
            )
        }
    }
}
