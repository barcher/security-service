package com.shared.security.application.ports

/**
 * **v0.2 amendment (Stream K, proposal §3.4b).** Narrow internal port over the KEK
 * wrap/unwrap surface, exposed inside the security service so the `jwt/` use cases
 * never import [CryptoKeyServicePort] directly.
 *
 * The two methods on this port are the only KEK operations any non-crypto code path
 * needs: wrap a plaintext blob, unwrap it later. The port surface deliberately excludes
 * KEK rotation, key generation, fingerprinting, and DEK lifecycle — those stay on the
 * wider [CryptoKeyServicePort] and are not relevant to JWT signing-key storage.
 *
 * **Exclusive implementer:** `com.shared.security.adapters.outbound.crypto.KekEnvelopeAdapter`.
 * Enforced by ArchUnit rule **S-13** (no other class may implement this interface).
 *
 * **Cross-module discipline.** Application code in `application/usecases/jwt/...` MUST
 * call this port, NEVER `CryptoKeyServicePort`. Enforced by ArchUnit rule **S-12** (no
 * class in `com.shared.security.application.usecases.jwt..` imports
 * `com.shared.security.application.ports.CryptoKeyServicePort`).
 *
 * **AAD requirement.** Every wrap binds an Additional Authenticated Data byte string;
 * the unwrap call must pass the same AAD or the AEAD tag verification fails. JWT
 * use cases pass `"jwt-signing-key:" + kid.toHex()` so a wrapped JWT-key blob cannot
 * be substituted for a DEK envelope under the same KEK.
 */
interface KekEnvelopePort {
    /**
     * Wrap [plaintext] under the current ACTIVE KEK, binding [aad] as the AEAD AAD.
     * The plaintext is zeroized after wrap.
     *
     * @throws IllegalStateException if no ACTIVE KEK is configured.
     */
    suspend fun wrap(
        plaintext: ByteArray,
        aad: ByteArray,
    ): WrappedBlob

    /**
     * Unwrap [wrapped] using the KEK identified by [WrappedBlob.kekId] (which may be
     * the ACTIVE KEK, a PRIOR KEK during a rotation window, or a legacy KEK during
     * the LRW transition). The same [aad] passed to [wrap] must be supplied here.
     *
     * @throws IllegalArgumentException if the AAD does not match (AEAD-tag mismatch).
     * @throws IllegalStateException if the referenced KEK is no longer reachable.
     */
    suspend fun unwrap(
        wrapped: WrappedBlob,
        aad: ByteArray,
    ): ByteArray
}

/**
 * A KEK-wrapped plaintext blob. Same wire shape as `WrappedDek` but a distinct
 * type in `application/ports/` so the JWT layer never imports crypto-layer types.
 *
 * - [kemCiphertextB64] — ML-KEM-768 ciphertext (base64)
 * - [encryptedBytesB64] — AES-256-GCM ciphertext (base64) covering `iv ‖ ct ‖ tag`
 * - [algorithm] — wrap-pipeline identifier (`ML-KEM-768/AES-256-GCM` today)
 * - [kekId] — UUID of the KEK row that produced this wrap; lets unwrap dispatch
 *   to the correct PRIOR or ACTIVE key during a rotation window
 */
data class WrappedBlob(
    val kemCiphertextB64: String,
    val encryptedBytesB64: String,
    val algorithm: String,
    val kekId: String,
)
