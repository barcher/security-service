package com.shared.security.application.ports

/**
 * Port for ML-KEM-768 DEK wrapping operations.
 *
 * All callers that need to generate, wrap, or unwrap a Data Encryption Key must go through
 * this port. The concrete implementation (MlKemCryptoKeyService) lives in
 * `adapters/outbound/crypto/` and is the ONLY class that may reference MlKemService directly.
 *
 * When the platform is split into discrete services, replace MlKemCryptoKeyService with an
 * HTTP/gRPC client adapter — the interface remains unchanged.
 */
interface CryptoKeyServicePort {
    data class GeneratedDek(
        /** Wrapped DEK ready to persist in the DB. */
        val wrapped: WrappedDek,
        /**
         * Plaintext DEK bytes for immediate use by the caller.
         * **Must be zeroised after use**: `plaintextBytes.fill(0)`.
         */
        val plaintextBytes: ByteArray,
    )

    /** Generate a fresh DEK and wrap it under the current KEK. */
    suspend fun generateDek(): GeneratedDek

    /** Wrap existing plaintext [dekBytes] under the current KEK. */
    suspend fun wrapDek(dekBytes: ByteArray): WrappedDek

    /** Unwrap a stored DEK using the current KEK private key. */
    suspend fun unwrapDek(wrapped: WrappedDek): ByteArray

    /**
     * Unwrap [existingWrapped] with the current KEK private key, then re-wrap the DEK
     * bytes under [newPublicKeyBytes]. Used during KEK rotation.
     */
    suspend fun rewrapDekForNewKek(
        existingWrapped: WrappedDek,
        newPublicKeyBytes: ByteArray,
    ): WrappedDek

    /**
     * Generate a new ML-KEM-768 keypair for KEK rotation preparation.
     * Returns base64-encoded (publicKey, privateKey). Store the private key securely —
     * it will become the new ML_KEM_PRIVATE_KEY after rotation completes.
     */
    fun generateNewKekPair(): KekPair

    /** SHA-256 fingerprint of the public KEK in colon-hex notation. Safe to display. */
    fun getPublicKeyFingerprint(): String

    /** True when ML-KEM keys are configured; false in NoOp/dev mode. */
    val isAvailable: Boolean
}

data class WrappedDek(
    val kemCiphertextB64: String,
    val encryptedDekB64: String,
    val algorithm: String = "ML-KEM-768/AES-256-GCM",
)

data class KekPair(val publicKeyB64: String, val privateKeyB64: String)
