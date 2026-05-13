package com.workautomations.security.adapters.outbound.crypto

import com.workautomations.security.application.ports.CryptoKeyServicePort
import com.workautomations.security.application.ports.KekPair
import com.workautomations.security.application.ports.WrappedDek
import java.util.Base64

/**
 * ML-KEM-768 + HKDF-SHA-512 implementation of [CryptoKeyServicePort].
 *
 * This is the sole class in this module that may reference [MlKemService] directly;
 * enforced by `CryptoBoundaryArchTest` rule S-3.
 */
class MlKemCryptoKeyService(private val mlKemService: MlKemService) : CryptoKeyServicePort {
    override val isAvailable: Boolean = true

    override suspend fun generateDek(): CryptoKeyServicePort.GeneratedDek {
        val out = mlKemService.generateAndWrapDek()
        return CryptoKeyServicePort.GeneratedDek(
            wrapped = WrappedDek(kemCiphertextB64 = out.kemCiphertextB64, encryptedDekB64 = out.encryptedDekB64),
            plaintextBytes = out.plaintextDek,
        )
    }

    override suspend fun wrapDek(dekBytes: ByteArray): WrappedDek {
        val (kemB64, encB64) = mlKemService.wrapDek(dekBytes)
        return WrappedDek(kemCiphertextB64 = kemB64, encryptedDekB64 = encB64)
    }

    override suspend fun unwrapDek(wrapped: WrappedDek): ByteArray =
        mlKemService.decapsulateAndUnwrapDek(wrapped.kemCiphertextB64, wrapped.encryptedDekB64)

    override suspend fun rewrapDekForNewKek(
        existingWrapped: WrappedDek,
        newPublicKeyBytes: ByteArray,
    ): WrappedDek {
        val dekBytes =
            mlKemService.decapsulateAndUnwrapDek(
                existingWrapped.kemCiphertextB64,
                existingWrapped.encryptedDekB64,
            )
        return try {
            val (newKemB64, newEncDekB64) = MlKemService.wrapDekForPublicKey(dekBytes, newPublicKeyBytes)
            WrappedDek(kemCiphertextB64 = newKemB64, encryptedDekB64 = newEncDekB64)
        } finally {
            dekBytes.fill(0)
        }
    }

    override fun generateNewKekPair(): KekPair {
        val (pub, priv) = MlKemService.generateKeyPair()
        return KekPair(publicKeyB64 = pub, privateKeyB64 = priv)
    }

    override fun getPublicKeyFingerprint(): String = mlKemService.getPublicKeyFingerprint()

    companion object {
        /** Construct from Base64-encoded env var values. Returns null when vars are absent. */
        fun fromEnv(): MlKemCryptoKeyService? {
            val svc = MlKemService.fromEnv() ?: return null
            return MlKemCryptoKeyService(svc)
        }

        /** Construct from raw key bytes. */
        fun fromBytes(
            publicKeyBytes: ByteArray,
            privateKeyBytes: ByteArray,
        ): MlKemCryptoKeyService = MlKemCryptoKeyService(MlKemService(publicKeyBytes, privateKeyBytes))

        fun fromBase64(
            publicKeyB64: String,
            privateKeyB64: String,
        ): MlKemCryptoKeyService =
            fromBytes(
                Base64.getDecoder().decode(publicKeyB64),
                Base64.getDecoder().decode(privateKeyB64),
            )
    }
}
