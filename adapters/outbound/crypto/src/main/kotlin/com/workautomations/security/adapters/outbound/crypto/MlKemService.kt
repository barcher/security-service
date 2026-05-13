package com.workautomations.security.adapters.outbound.crypto

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Post-quantum KEM service backed by Bouncy Castle ML-KEM-768 (FIPS 203).
 *
 * ML-KEM-768 provides 192-bit post-quantum security (IND-CCA2). The public key encapsulates a
 * fresh 32-byte shared secret which is then expanded with **HKDF-SHA-512** into:
 *   - bytes 0..31  → 32-byte AES-256-GCM wrap key
 *   - bytes 32..63 → 32-byte auth-domain-separator sub-key, bound into the AEAD AAD
 *
 * The AEAD AAD is `WRAP_AAD_PREFIX || ad_subkey`. Tampering with either the wrapped DEK
 * material or the upstream shared secret is detected on decrypt as a tag-validation failure.
 *
 * **This is the Phase 14 wrap algorithm.** It is NOT compatible with the Phase 12 `enc:v0:`
 * or `enc:v2:` envelope formats — those are read-only in the monolith and migrated in bulk by
 * Stream E (`LegacyEnvelopeRewriteJob`).
 *
 * This class is an internal implementation detail of [MlKemCryptoKeyService]. No class outside
 * `com.workautomations.security.adapters.outbound.crypto` may reference it directly; enforced
 * by `CryptoBoundaryArchTest` rule S-3.
 */
class MlKemService(
    private val publicKeyBytes: ByteArray,
    private val privateKeyBytes: ByteArray,
) {
    private val publicKey = MLKEMPublicKeyParameters(ML_KEM_PARAMS, publicKeyBytes)
    private val privateKey = MLKEMPrivateKeyParameters(ML_KEM_PARAMS, privateKeyBytes)
    private val secureRandom = SecureRandom()

    data class WrapOutput(
        val kemCiphertextB64: String,
        val encryptedDekB64: String,
        val plaintextDek: ByteArray,
    )

    /** Generate a fresh DEK, KEM-encapsulate, HKDF-expand, AES-256-GCM wrap. */
    fun generateAndWrapDek(): WrapOutput {
        val dekBytes = ByteArray(DEK_BYTES)
        secureRandom.nextBytes(dekBytes)
        val (kemB64, encB64) = wrapBytes(dekBytes, publicKey, secureRandom)
        return WrapOutput(kemCiphertextB64 = kemB64, encryptedDekB64 = encB64, plaintextDek = dekBytes)
    }

    /** Re-wrap existing [dekBytes] under the current public key — DEK identity preserved. */
    fun wrapDek(dekBytes: ByteArray): Pair<String, String> = wrapBytes(dekBytes, publicKey, secureRandom)

    /** Decapsulate + HKDF-expand + AES-GCM unwrap. Returns 32-byte DEK. */
    fun decapsulateAndUnwrapDek(
        kemCiphertextB64: String,
        encryptedDekB64: String,
    ): ByteArray {
        val kemCiphertext = Base64.getDecoder().decode(kemCiphertextB64)
        val encryptedDek = Base64.getDecoder().decode(encryptedDekB64)

        val sharedSecret = MLKEMExtractor(privateKey).extractSecret(kemCiphertext)
        return try {
            val (aesKey, adSubkey) = deriveKeys(sharedSecret)
            try {
                aesGcmDecrypt(encryptedDek, aesKey, WRAP_AAD_PREFIX + adSubkey)
            } finally {
                aesKey.fill(0)
                adSubkey.fill(0)
            }
        } finally {
            sharedSecret.fill(0)
        }
    }

    /** SHA-256 fingerprint of the public key in colon-hex notation. Safe to display. */
    fun getPublicKeyFingerprint(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKeyBytes)
        return digest.joinToString(":") { "%02x".format(it) }
    }

    companion object {
        internal val ML_KEM_PARAMS = MLKEMParameters.ml_kem_768
        const val DEK_BYTES = 32

        /** Expected public key size in bytes for ML-KEM-768. */
        const val PUBLIC_KEY_BYTES = 1184

        /** Expected private key size in bytes for ML-KEM-768. */
        const val PRIVATE_KEY_BYTES = 2400

        /** Domain-separation prefix for the AEAD AAD. Versioned for forward-compatibility. */
        internal val WRAP_AAD_PREFIX: ByteArray = "WA.Security.MlKemWrap.v1".toByteArray(Charsets.US_ASCII)

        /** HKDF `info` label. Different value than [WRAP_AAD_PREFIX] so the two layers can evolve independently. */
        internal val HKDF_INFO: ByteArray = "WA.Security.MlKemWrap.HKDF.v1".toByteArray(Charsets.US_ASCII)

        private const val AES_ALGORITHM = "AES"
        private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_BITS = 128
        private const val HKDF_OKM_BYTES = 64

        /**
         * Wrap [dekBytes] under [publicKeyBytes] without requiring the private key.
         * Used during KEK rotation: existing DEK is unwrapped with the OLD private key, then
         * re-wrapped here under the NEW public key.
         */
        fun wrapDekForPublicKey(
            dekBytes: ByteArray,
            publicKeyBytes: ByteArray,
        ): Pair<String, String> {
            val targetPublicKey = MLKEMPublicKeyParameters(ML_KEM_PARAMS, publicKeyBytes)
            return wrapBytes(dekBytes, targetPublicKey, SecureRandom())
        }

        /** Generates a new ML-KEM-768 key pair. Returns (base64 public, base64 private). */
        fun generateKeyPair(): Pair<String, String> {
            val kpg = MLKEMKeyPairGenerator()
            kpg.init(MLKEMKeyGenerationParameters(SecureRandom(), ML_KEM_PARAMS))
            val kp = kpg.generateKeyPair()
            val pub = (kp.public as MLKEMPublicKeyParameters).encoded
            val priv = (kp.private as MLKEMPrivateKeyParameters).encoded
            return Base64.getEncoder().encodeToString(pub) to Base64.getEncoder().encodeToString(priv)
        }

        /** Construct from env vars `ML_KEM_PUBLIC_KEY` / `ML_KEM_PRIVATE_KEY`. Returns null if unset. */
        fun fromEnv(): MlKemService? {
            val pub = System.getenv("ML_KEM_PUBLIC_KEY") ?: return null
            val priv = System.getenv("ML_KEM_PRIVATE_KEY") ?: return null
            return runCatching {
                MlKemService(
                    Base64.getDecoder().decode(pub),
                    Base64.getDecoder().decode(priv),
                )
            }.getOrElse {
                error("ML_KEM_PUBLIC_KEY or ML_KEM_PRIVATE_KEY is not valid Base64: ${it.message}")
            }
        }

        /**
         * Shared encryption path used by instance + static wrap helpers.
         *
         * Pipeline:
         *   1. KEM encapsulate against [targetPublicKey] → shared_secret (32 bytes), kem_ciphertext (1088 bytes).
         *   2. HKDF-SHA-512 expand shared_secret with `info=HKDF_INFO`, salt=null → 64 bytes OKM.
         *   3. aes_key = okm[0..32); ad_subkey = okm[32..64).
         *   4. AES-256-GCM encrypt(plaintext=dekBytes, key=aes_key, iv=random12, aad=WRAP_AAD_PREFIX||ad_subkey).
         *   5. Zeroize transient material (shared_secret, aes_key, ad_subkey).
         *
         * Returns (base64 kem_ciphertext, base64 iv||ciphertext||tag).
         */
        private fun wrapBytes(
            dekBytes: ByteArray,
            targetPublicKey: MLKEMPublicKeyParameters,
            random: SecureRandom,
        ): Pair<String, String> {
            val kemGen = MLKEMGenerator(random)
            val secretWithEnc = kemGen.generateEncapsulated(targetPublicKey)
            val sharedSecret = secretWithEnc.secret
            val kemCiphertext = secretWithEnc.encapsulation
            secretWithEnc.destroy()

            return try {
                val (aesKey, adSubkey) = deriveKeys(sharedSecret)
                try {
                    val encryptedDek = aesGcmEncrypt(dekBytes, aesKey, WRAP_AAD_PREFIX + adSubkey, random)
                    Base64.getEncoder().encodeToString(kemCiphertext) to
                        Base64.getEncoder().encodeToString(encryptedDek)
                } finally {
                    aesKey.fill(0)
                    adSubkey.fill(0)
                }
            } finally {
                sharedSecret.fill(0)
            }
        }

        /** HKDF-SHA-512 expansion of [sharedSecret] → (aesKey 32B, adSubkey 32B). */
        internal fun deriveKeys(sharedSecret: ByteArray): Pair<ByteArray, ByteArray> {
            val hkdf = HKDFBytesGenerator(SHA512Digest())
            hkdf.init(HKDFParameters(sharedSecret, null, HKDF_INFO))
            val okm = ByteArray(HKDF_OKM_BYTES)
            hkdf.generateBytes(okm, 0, HKDF_OKM_BYTES)
            val aesKey = okm.copyOfRange(0, DEK_BYTES)
            val adSubkey = okm.copyOfRange(DEK_BYTES, HKDF_OKM_BYTES)
            okm.fill(0)
            return aesKey to adSubkey
        }

        private fun aesGcmEncrypt(
            plaintext: ByteArray,
            key: ByteArray,
            aad: ByteArray,
            random: SecureRandom,
        ): ByteArray {
            val iv = ByteArray(GCM_IV_LENGTH)
            random.nextBytes(iv)
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, AES_ALGORITHM), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            return iv + ciphertext
        }

        private fun aesGcmDecrypt(
            ivAndCiphertext: ByteArray,
            key: ByteArray,
            aad: ByteArray,
        ): ByteArray {
            val iv = ivAndCiphertext.copyOfRange(0, GCM_IV_LENGTH)
            val ciphertext = ivAndCiphertext.copyOfRange(GCM_IV_LENGTH, ivAndCiphertext.size)
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, AES_ALGORITHM), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext)
        }
    }
}
