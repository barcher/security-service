package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.JwtSigningKeyRecord
import com.shared.security.application.ports.JwtSigningKeyRepository
import com.shared.security.application.ports.JwtSigningKeyStatus
import com.shared.security.application.ports.KekEnvelopePort
import kotlinx.datetime.Clock

/**
 * SKS-K05 — Generate a fresh ES256 keypair, KEK-wrap the private bytes, and insert a
 * STAGED row in `jwt_signing_keys`. Mirrors [com.shared.security.application.usecases.GenerateDekUseCase]
 * in shape; differs in two respects:
 *
 *  1. Uses [KekEnvelopePort] (Stream K internal-port pattern) rather than
 *     [com.shared.security.application.ports.CryptoKeyServicePort] directly.
 *  2. The AAD bound at wrap time is `"jwt-signing-key:" + kid.toHex()` so a wrapped JWT
 *     private blob can never be substituted for a DEK envelope wrapped under the same
 *     KEK (the AEAD tag would fail to verify on the wrong-AAD code path).
 */
class GenerateJwtSigningKeyPairUseCase(
    private val signing: JwtSigningKeyPort,
    private val kekEnvelope: KekEnvelopePort,
    private val repo: JwtSigningKeyRepository,
    private val auditLog: AuditLogPort,
    private val clock: Clock = Clock.System,
) {
    suspend fun execute(actorSubject: String?): JwtSigningKeyRecord {
        val keyPair = signing.generateKeyPair()
        val kid = signing.computeKid(keyPair.publicKeySpki)
        val aad = aadFor(kid)

        // Make a defensive copy because KekEnvelopePort.wrap implementations zeroize the
        // input. The primitive's sign() path zeroizes a separate copy further down.
        val wrapInput = keyPair.privateKeyPkcs8.copyOf()
        val wrapped = kekEnvelope.wrap(wrapInput, aad)
        val wrappedBytes = WrappedBlobCodec.encode(wrapped)

        // The original `keyPair.privateKeyPkcs8` is no longer needed; zeroize.
        keyPair.privateKeyPkcs8.fill(0)

        val now = clock.now()
        val record =
            JwtSigningKeyRecord(
                kid = kid,
                status = JwtSigningKeyStatus.STAGED,
                algorithm = ALGORITHM,
                curve = CURVE,
                wrappedPrivateKeyBytes = wrappedBytes,
                publicKeySpki = keyPair.publicKeySpki,
                wrappedUnderKekId = wrapped.kekId,
                createdAt = now,
                activatedAt = null,
                quiescedAt = null,
                retiredAt = null,
                retainUntil = null,
            )

        repo.insertStaged(record)
        auditLog.write(
            AuditEvent(
                occurredAt = now,
                eventType = AuditEventType.JWKS_KEY_GENERATED,
                actorSubject = actorSubject,
                kekId = wrapped.kekId,
                success = true,
                detailJson = """{"kid":"${kid.toHex()}","alg":"$ALGORITHM","crv":"$CURVE"}""",
            ),
        )
        return record
    }

    private companion object {
        private const val ALGORITHM = "ES256"
        private const val CURVE = "P-256"
    }
}

internal fun aadFor(kid: ByteArray): ByteArray = ("jwt-signing-key:" + kid.toHex()).toByteArray(Charsets.UTF_8)

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
