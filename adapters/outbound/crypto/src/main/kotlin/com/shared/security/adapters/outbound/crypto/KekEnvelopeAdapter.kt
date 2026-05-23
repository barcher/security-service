package com.shared.security.adapters.outbound.crypto

import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.KekEnvelopePort
import com.shared.security.application.ports.KekRepository
import com.shared.security.application.ports.WrappedBlob
import com.shared.security.application.ports.WrappedDek
import org.slf4j.LoggerFactory

/**
 * **v0.2 amendment (Stream K, proposal §3.4b).** The EXCLUSIVE bridge between the
 * `crypto/` and `jwt/` sub-modules within the security service. Implements the narrow
 * [KekEnvelopePort] (consumed by `jwt/` use cases) by delegating to the wider
 * [CryptoKeyServicePort].
 *
 * **AAD binding strategy.** [CryptoKeyServicePort.wrapDek] does not expose an AAD
 * parameter; AAD binding happens internally to the AEAD construction. Stream K adds
 * the requirement to bind a caller-supplied AAD (so a wrapped JWT-key blob cannot be
 * substituted for a DEK envelope under the same KEK). The adapter implements this by
 * prepending a length-prefixed AAD field to the plaintext before calling `wrapDek`:
 *
 *     prefix = aad.length (4-byte big-endian) ‖ aad ‖ plaintext
 *
 * On unwrap, the prefix is parsed and the caller-supplied AAD compared against the
 * embedded copy. A mismatch raises [IllegalArgumentException] without revealing which
 * field differs (constant-time comparison). This is cryptographically equivalent to
 * AEAD AAD: any tampering with either the AAD field or the plaintext invalidates the
 * AEAD tag in the underlying wrap.
 *
 * ArchUnit rule **S-13** (lands in SKS-K01a alongside this class) ensures this is the
 * ONLY class that implements `KekEnvelopePort`. Any future bypass of the narrow port
 * fails the build.
 */
class KekEnvelopeAdapter(
    private val cryptoKeyService: CryptoKeyServicePort,
    private val kekRepository: KekRepository,
) : KekEnvelopePort {
    private val log = LoggerFactory.getLogger(KekEnvelopeAdapter::class.java)

    override suspend fun wrap(
        plaintext: ByteArray,
        aad: ByteArray,
    ): WrappedBlob {
        require(aad.size in 1..MAX_AAD_BYTES) { "AAD must be 1..$MAX_AAD_BYTES bytes" }
        val activeKek =
            kekRepository.findActive()
                ?: error("No ACTIVE KEK; cannot wrap. Run HSM ceremony per HSM_KEY_CEREMONY.md §2.")
        val composite = composeForWrap(aad, plaintext)
        try {
            val wrapped = cryptoKeyService.wrapDek(composite)
            return WrappedBlob(
                kemCiphertextB64 = wrapped.kemCiphertextB64,
                encryptedBytesB64 = wrapped.encryptedDekB64,
                algorithm = wrapped.algorithm,
                kekId = activeKek.id,
            )
        } finally {
            composite.fill(0)
        }
    }

    override suspend fun unwrap(
        wrapped: WrappedBlob,
        aad: ByteArray,
    ): ByteArray {
        val composite =
            cryptoKeyService.unwrapDek(
                WrappedDek(
                    kemCiphertextB64 = wrapped.kemCiphertextB64,
                    encryptedDekB64 = wrapped.encryptedBytesB64,
                    algorithm = wrapped.algorithm,
                ),
            )
        try {
            return splitAndVerify(composite, aad)
        } finally {
            composite.fill(0)
        }
    }

    private fun composeForWrap(
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        // Length-prefixed AAD field: [aad.size as 4-byte BE][aad][plaintext]
        val composite = ByteArray(LENGTH_PREFIX_BYTES + aad.size + plaintext.size)
        composite[0] = (aad.size ushr 24).toByte()
        composite[1] = (aad.size ushr 16).toByte()
        composite[2] = (aad.size ushr 8).toByte()
        composite[3] = aad.size.toByte()
        System.arraycopy(aad, 0, composite, LENGTH_PREFIX_BYTES, aad.size)
        System.arraycopy(plaintext, 0, composite, LENGTH_PREFIX_BYTES + aad.size, plaintext.size)
        return composite
    }

    private fun splitAndVerify(
        composite: ByteArray,
        expectedAad: ByteArray,
    ): ByteArray {
        require(composite.size >= LENGTH_PREFIX_BYTES) { "Wrapped blob is too short to be valid" }
        val embeddedAadLen =
            ((composite[0].toInt() and 0xFF) shl 24) or
                ((composite[1].toInt() and 0xFF) shl 16) or
                ((composite[2].toInt() and 0xFF) shl 8) or
                (composite[3].toInt() and 0xFF)
        require(embeddedAadLen in 1..MAX_AAD_BYTES) { "Wrapped blob has malformed AAD length" }
        require(composite.size >= LENGTH_PREFIX_BYTES + embeddedAadLen) {
            "Wrapped blob is too short for the embedded AAD"
        }
        val embeddedAad = composite.copyOfRange(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + embeddedAadLen)
        if (!constantTimeEquals(embeddedAad, expectedAad)) {
            // Do not leak which field differs.
            log.warn("KekEnvelopeAdapter.unwrap: AAD mismatch — wrapped blob does not bind to the expected context")
            throw IllegalArgumentException("AAD verification failed")
        }
        return composite.copyOfRange(LENGTH_PREFIX_BYTES + embeddedAadLen, composite.size)
    }

    private fun constantTimeEquals(
        a: ByteArray,
        b: ByteArray,
    ): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    private companion object {
        const val LENGTH_PREFIX_BYTES = 4
        const val MAX_AAD_BYTES = 4096
    }
}
