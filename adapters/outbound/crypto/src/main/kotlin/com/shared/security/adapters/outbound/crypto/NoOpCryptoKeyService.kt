package com.shared.security.adapters.outbound.crypto

import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.KekPair
import com.shared.security.application.ports.WrappedDek

/**
 * No-op implementation of [CryptoKeyServicePort] for dev/test wiring where the KEK is not
 * configured. All operations that need key material throw; `isAvailable=false` signals to
 * startup probes that production crypto is not wired. [generateNewKekPair] still works
 * (the static ML-KEM key generator does not need a private key).
 */
object NoOpCryptoKeyService : CryptoKeyServicePort {
    private const val NOT_CONFIGURED =
        "ML-KEM keys not configured — security-service requires a real KEK in prod"

    override val isAvailable: Boolean = false

    override suspend fun generateDek(): CryptoKeyServicePort.GeneratedDek = error(NOT_CONFIGURED)

    override suspend fun wrapDek(dekBytes: ByteArray): WrappedDek = error(NOT_CONFIGURED)

    override suspend fun unwrapDek(wrapped: WrappedDek): ByteArray = error(NOT_CONFIGURED)

    override suspend fun rewrapDekForNewKek(
        existingWrapped: WrappedDek,
        newPublicKeyBytes: ByteArray,
    ): WrappedDek = error(NOT_CONFIGURED)

    override fun generateNewKekPair(): KekPair {
        val (pub, priv) = MlKemService.generateKeyPair()
        return KekPair(publicKeyB64 = pub, privateKeyB64 = priv)
    }

    override fun getPublicKeyFingerprint(): String = error(NOT_CONFIGURED)
}
