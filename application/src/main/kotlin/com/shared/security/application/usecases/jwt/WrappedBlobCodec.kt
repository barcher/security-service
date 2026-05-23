package com.shared.security.application.usecases.jwt

import com.shared.security.application.ports.WrappedBlob
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Persistent encoding for [WrappedBlob] used by the JWT signing-key adapter. The blob is
 * stored as JSON bytes in `jwt_signing_keys.wrapped_private_key_bytes` so the four-field
 * envelope (KEM ciphertext, AES-GCM ciphertext, algorithm, kekId) round-trips losslessly.
 *
 * JSON over a more compact framing is chosen because:
 *   1. The two base64 strings are already textual; converting them to a binary framing
 *      would only save the JSON brackets and key names.
 *   2. JSON is human-readable for the operator decrypt CLI when investigating an
 *      individual row.
 *   3. The `algorithm` field is required for forward-compatibility once a second wrap
 *      pipeline is added; a JSON envelope versions cleanly.
 */
object WrappedBlobCodec {
    private val json = Json { ignoreUnknownKeys = true }

    fun encode(wrapped: WrappedBlob): ByteArray =
        json.encodeToString(
            EnvelopeJson.serializer(),
            EnvelopeJson(
                kem = wrapped.kemCiphertextB64,
                enc = wrapped.encryptedBytesB64,
                alg = wrapped.algorithm,
                kekId = wrapped.kekId,
            ),
        ).toByteArray(Charsets.UTF_8)

    fun decode(bytes: ByteArray): WrappedBlob {
        val parsed = json.decodeFromString(EnvelopeJson.serializer(), bytes.toString(Charsets.UTF_8))
        return WrappedBlob(
            kemCiphertextB64 = parsed.kem,
            encryptedBytesB64 = parsed.enc,
            algorithm = parsed.alg,
            kekId = parsed.kekId,
        )
    }

    @Serializable
    private data class EnvelopeJson(
        val kem: String,
        val enc: String,
        val alg: String,
        val kekId: String,
    )
}
