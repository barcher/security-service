package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtAudienceAllowList
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.KekEnvelopePort
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.Base64

/**
 * SKS-K07 — Mint an ES256 JWT for a verified mTLS caller.
 *
 * Flow per proposal §3.4a (two-gate auth) + §5.1 (sign endpoint):
 *
 *   1. Gate-2 check: `audienceAllowList.isAllowed(subjectDn, audience)`. Fail →
 *      emit `JWT_AUDIENCE_FORBIDDEN` audit and return [Result.AudienceForbidden].
 *      The mTLS Gate-1 check is already done by the route layer before this use
 *      case is invoked.
 *   2. Load the ACTIVE signing key. Missing → emit `JWT_SIGN_FAILED` audit and
 *      return [Result.NoActiveKey]. This is a 503 from the route layer.
 *   3. Unwrap the private bytes via [KekEnvelopePort] (the AAD matches what
 *      [GenerateJwtSigningKeyPairUseCase] bound at wrap time).
 *   4. Build the JWT header + payload, base64url-encode each, join with a `.`,
 *      and sign the resulting bytes. Append `.<base64url-signature>`.
 *   5. Emit `JWT_SIGNED` audit and return [Result.Signed].
 *
 * The private bytes are zeroized after sign() returns (the primitive contract guarantees
 * its internal zeroization; this use case zeroizes its own copy).
 */
@Suppress("LongParameterList")
class SignJwtUseCase(
    private val repo: JwtSigningKeyRepository,
    private val kekEnvelope: KekEnvelopePort,
    private val signing: JwtSigningKeyPort,
    private val audienceAllowList: JwtAudienceAllowList,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(request: Request): Result {
        if (!audienceAllowList.isAllowed(request.subjectDn, request.audience)) {
            auditLog.write(
                AuditEvent(
                    occurredAt = clock.now(),
                    eventType = AuditEventType.JWT_AUDIENCE_FORBIDDEN,
                    actorSubject = request.subjectDn,
                    success = false,
                    detailJson = """{"audience":"${request.audience.jsonEscaped()}"}""",
                ),
            )
            return Result.AudienceForbidden
        }

        val activeKey =
            repo.findActive() ?: run {
                auditLog.write(
                    AuditEvent(
                        occurredAt = clock.now(),
                        eventType = AuditEventType.JWT_SIGN_FAILED,
                        actorSubject = request.subjectDn,
                        success = false,
                        detailJson = """{"reason":"no_active_signing_key"}""",
                    ),
                )
                return Result.NoActiveKey
            }

        val wrapped = WrappedBlobCodec.decode(activeKey.wrappedPrivateKeyBytes)
        val aad = aadFor(activeKey.kid)
        val privateKeyPkcs8 = kekEnvelope.unwrap(wrapped, aad)

        val now = clock.now()
        val expiresAt = Instant.fromEpochSeconds(now.epochSeconds + request.expiresInSeconds)

        val signingInput =
            buildSigningInput(
                kid = activeKey.kid,
                subject = request.subject,
                audience = request.audience,
                issuer = request.issuer,
                expiresAt = expiresAt,
                issuedAt = now,
                extraClaims = request.extraClaims,
            )

        val signature: ByteArray
        try {
            signature = signing.sign(privateKeyPkcs8.copyOf(), signingInput)
        } catch (ex: Exception) {
            auditLog.write(
                AuditEvent(
                    occurredAt = clock.now(),
                    eventType = AuditEventType.JWT_SIGN_FAILED,
                    actorSubject = request.subjectDn,
                    success = false,
                    detailJson = """{"reason":"sign_threw","exception":"${ex.javaClass.simpleName}"}""",
                ),
            )
            throw ex
        } finally {
            privateKeyPkcs8.fill(0)
        }

        val token = signingInput.toString(Charsets.US_ASCII) + "." + B64URL.encodeToString(signature)
        auditLog.write(
            AuditEvent(
                occurredAt = now,
                eventType = AuditEventType.JWT_SIGNED,
                actorSubject = request.subjectDn,
                kekId = activeKey.wrappedUnderKekId,
                success = true,
                detailJson =
                    """{"kid":"${activeKey.kid.toHex()}","aud":"${request.audience.jsonEscaped()}",""" +
                        """"sub":"${request.subject.jsonEscaped()}","exp":${expiresAt.epochSeconds}}""",
            ),
        )
        return Result.Signed(token = token, kid = activeKey.kid, expiresAt = expiresAt)
    }

    private fun buildSigningInput(
        kid: ByteArray,
        subject: String,
        audience: String,
        issuer: String,
        expiresAt: Instant,
        issuedAt: Instant,
        extraClaims: Map<String, JsonElement>,
    ): ByteArray {
        val header = """{"alg":"ES256","typ":"JWT","kid":"${kid.toHex()}"}"""
        val claims =
            buildMap<String, JsonElement> {
                put("iss", JsonPrimitive(issuer))
                put("sub", JsonPrimitive(subject))
                put("aud", JsonPrimitive(audience))
                put("iat", JsonPrimitive(issuedAt.epochSeconds))
                put("exp", JsonPrimitive(expiresAt.epochSeconds))
                putAll(extraClaims)
            }
        val payload = Json.encodeToString(JsonObject.serializer(), JsonObject(claims))

        val headerB64 = B64URL.encodeToString(header.toByteArray(Charsets.UTF_8))
        val payloadB64 = B64URL.encodeToString(payload.toByteArray(Charsets.UTF_8))
        return "$headerB64.$payloadB64".toByteArray(Charsets.US_ASCII)
    }

    data class Request(
        val subjectDn: String,
        val subject: String,
        val audience: String,
        val issuer: String,
        val expiresInSeconds: Long,
        val extraClaims: Map<String, JsonElement> = emptyMap(),
    )

    sealed interface Result {
        data class Signed(
            val token: String,
            val kid: ByteArray,
            val expiresAt: Instant,
        ) : Result {
            override fun equals(other: Any?): Boolean = this === other

            override fun hashCode(): Int = System.identityHashCode(this)
        }

        data object AudienceForbidden : Result

        data object NoActiveKey : Result
    }

    private companion object {
        private val B64URL: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    }
}

private fun String.jsonEscaped(): String = replace("\\", "\\\\").replace("\"", "\\\"")
