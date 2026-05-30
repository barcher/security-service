package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.dto.EmailBlindIndexRequest
import com.shared.security.adapters.inbound.http.dto.EmailBlindIndexResponse
import com.shared.security.adapters.inbound.http.dto.ErrorResponse
import com.shared.security.adapters.inbound.http.dto.FinancialDedupBlindIndexRequest
import com.shared.security.adapters.inbound.http.dto.FinancialDedupBlindIndexResponse
import com.shared.security.application.usecases.blindindex.ComputeEmailBlindIndexUseCase
import com.shared.security.application.usecases.blindindex.ComputeFinancialDedupBlindIndexUseCase
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import java.util.Base64

/**
 * Blind-index routes. Run only after [MtlsAuthPlugin] has authenticated the caller over the
 * operational lane (the monolith for email; financial-service for dedup). Each computes a
 * one-way keyed HMAC; the HMAC keys never leave the security service.
 *
 * Two purposes, two keys, two namespaces:
 *   - `/email` — HMAC over the normalized plaintext email (16-byte truncated). Backs the
 *     monolith's `company_candidates.email` blind-index lookup.
 *   - `/financial-dedup` — HMAC over a caller-supplied 32-byte SHA-256 PREHASH (full 32-byte
 *     output). Backs financial-service's transaction dedup blind index. The caller prehashes
 *     locally so the (encrypted-at-rest) merchant token never crosses the wire.
 *
 * Deliberately writes NO audit row per call (routine, high-volume, one-way) and NEVER logs
 * the request payload — enforced by ArchUnit S-22 (no logger reference in this file).
 */
fun Routing.installBlindIndexRoutes(
    computeEmailBlindIndex: ComputeEmailBlindIndexUseCase,
    computeFinancialDedupBlindIndex: ComputeFinancialDedupBlindIndexUseCase,
) {
    val b64Encoder = Base64.getEncoder()
    val b64Decoder = Base64.getDecoder()

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
        post("/financial-dedup") {
            val request = call.receive<FinancialDedupBlindIndexRequest>()
            val prehash =
                runCatching { b64Decoder.decode(request.prehashB64) }.getOrElse {
                    call.respond(HttpStatusCode.UnprocessableEntity, ErrorResponse("prehash_invalid_base64"))
                    return@post
                }
            if (prehash.size != SHA256_BYTES) {
                call.respond(HttpStatusCode.UnprocessableEntity, ErrorResponse("prehash_must_be_sha256"))
                return@post
            }
            val hash = computeFinancialDedupBlindIndex.compute(prehash)
            call.respond(
                HttpStatusCode.OK,
                FinancialDedupBlindIndexResponse(blindIndexB64 = b64Encoder.encodeToString(hash)),
            )
        }
    }
}

private const val SHA256_BYTES = 32
