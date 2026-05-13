package com.workautomations.security.adapters.inbound.http

import com.workautomations.security.adapters.inbound.http.auth.clientPrincipal
import com.workautomations.security.adapters.inbound.http.dto.ErrorResponse
import com.workautomations.security.adapters.inbound.http.dto.GenerateDekResponse
import com.workautomations.security.adapters.inbound.http.dto.RewrapDekRequest
import com.workautomations.security.adapters.inbound.http.dto.RewrapDekResponse
import com.workautomations.security.adapters.inbound.http.dto.UnwrapDekRequest
import com.workautomations.security.adapters.inbound.http.dto.UnwrapDekResponse
import com.workautomations.security.adapters.inbound.http.dto.WrapDekRequest
import com.workautomations.security.adapters.inbound.http.dto.WrapDekResponse
import com.workautomations.security.adapters.inbound.http.dto.WrappedDekDto
import com.workautomations.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditEventType
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.application.ports.WrappedDek
import com.workautomations.security.application.usecases.GenerateDekUseCase
import com.workautomations.security.application.usecases.RewrapDekUseCase
import com.workautomations.security.application.usecases.UnwrapDekUseCase
import com.workautomations.security.application.usecases.WrapDekUseCase
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import kotlinx.datetime.Clock
import java.util.Base64
import javax.crypto.AEADBadTagException

/**
 * Crypto routes — every endpoint runs only after [MtlsAuthPlugin] has populated
 * `call.clientPrincipal()`. The principal's subject DN is propagated to the use cases as
 * `actorSubject` so every audit event identifies the calling service.
 *
 * DEK_BYTES is the only invariant enforced at the wire boundary; everything else is
 * delegated to the crypto layer (which raises `AEADBadTagException` or
 * `IllegalArgumentException` on tampered / malformed input).
 */
private const val EXPECTED_DEK_BYTES = 32

fun Routing.installCryptoRoutes(
    generateDek: GenerateDekUseCase,
    wrapDek: WrapDekUseCase,
    unwrapDek: UnwrapDekUseCase,
    rewrapDek: RewrapDekUseCase,
    unwrapRateLimiter: PerSubjectRateLimiter? = null,
    auditLog: AuditLogPort? = null,
) {
    val b64Encoder = Base64.getEncoder()
    val b64Decoder = Base64.getDecoder()

    route("/v1/dek") {
        post("/generate") {
            val subject = call.clientPrincipal()?.subjectDn
            val result = generateDek.execute(actorSubject = subject)
            try {
                call.respond(
                    HttpStatusCode.OK,
                    GenerateDekResponse(
                        wrapped = result.wrapped.toDto(),
                        plaintextDekB64 = b64Encoder.encodeToString(result.plaintextBytes),
                    ),
                )
            } finally {
                result.plaintextBytes.fill(0)
            }
        }

        post("/wrap") {
            val req = call.receive<WrapDekRequest>()
            val dekBytes =
                runCatching { b64Decoder.decode(req.dekBytesB64) }.getOrElse {
                    return@post call.respond(
                        HttpStatusCode.UnprocessableEntity,
                        ErrorResponse("malformed_request", "dekBytesB64 is not valid base64"),
                    )
                }
            if (dekBytes.size != EXPECTED_DEK_BYTES) {
                return@post call.respond(
                    HttpStatusCode.UnprocessableEntity,
                    ErrorResponse("malformed_request", "dekBytesB64 must decode to $EXPECTED_DEK_BYTES bytes"),
                )
            }
            val subject = call.clientPrincipal()?.subjectDn
            val wrapped = wrapDek.execute(dekBytes = dekBytes, actorSubject = subject)
            dekBytes.fill(0)
            call.respond(HttpStatusCode.OK, WrapDekResponse(wrapped.toDto()))
        }

        post("/unwrap") {
            val req = call.receive<UnwrapDekRequest>()
            val subject = call.clientPrincipal()?.subjectDn
            if (unwrapRateLimiter != null && subject != null && !unwrapRateLimiter.tryConsume(subject)) {
                auditLog?.write(
                    AuditEvent(
                        occurredAt = Clock.System.now(),
                        eventType = AuditEventType.RATE_LIMIT_EXCEEDED,
                        actorSubject = subject,
                        success = false,
                        detailJson = """{"endpoint":"/v1/dek/unwrap"}""",
                    ),
                )
                return@post call.respond(HttpStatusCode.TooManyRequests, ErrorResponse("rate_limited"))
            }
            val plaintext =
                try {
                    unwrapDek.execute(req.wrapped.toDomain(), actorSubject = subject)
                } catch (_: AEADBadTagException) {
                    return@post call.respond(
                        HttpStatusCode.UnprocessableEntity,
                        ErrorResponse("aead_tag_mismatch"),
                    )
                } catch (e: IllegalArgumentException) {
                    return@post call.respond(
                        HttpStatusCode.UnprocessableEntity,
                        ErrorResponse("malformed_request", e.message),
                    )
                }
            try {
                call.respond(
                    HttpStatusCode.OK,
                    UnwrapDekResponse(plaintextDekB64 = b64Encoder.encodeToString(plaintext)),
                )
            } finally {
                plaintext.fill(0)
            }
        }

        post("/rewrap") {
            val req = call.receive<RewrapDekRequest>()
            val newPubBytes =
                runCatching { b64Decoder.decode(req.newPublicKeyB64) }.getOrElse {
                    return@post call.respond(
                        HttpStatusCode.UnprocessableEntity,
                        ErrorResponse("malformed_request", "newPublicKeyB64 is not valid base64"),
                    )
                }
            val subject = call.clientPrincipal()?.subjectDn
            val rewrapped =
                try {
                    rewrapDek.execute(
                        existing = req.existing.toDomain(),
                        newPublicKeyBytes = newPubBytes,
                        actorSubject = subject,
                    )
                } catch (_: AEADBadTagException) {
                    return@post call.respond(
                        HttpStatusCode.UnprocessableEntity,
                        ErrorResponse("aead_tag_mismatch"),
                    )
                }
            call.respond(HttpStatusCode.OK, RewrapDekResponse(rewrapped.toDto()))
        }
    }
}

private fun WrappedDek.toDto(): WrappedDekDto =
    WrappedDekDto(
        kemCiphertextB64 = kemCiphertextB64,
        encryptedDekB64 = encryptedDekB64,
        algorithm = algorithm,
    )

private fun WrappedDekDto.toDomain(): WrappedDek =
    WrappedDek(
        kemCiphertextB64 = kemCiphertextB64,
        encryptedDekB64 = encryptedDekB64,
        algorithm = algorithm,
    )
