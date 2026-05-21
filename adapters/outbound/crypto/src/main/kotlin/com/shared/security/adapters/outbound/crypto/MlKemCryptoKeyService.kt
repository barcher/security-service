package com.shared.security.adapters.outbound.crypto

import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.KekPair
import com.shared.security.application.ports.WrappedDek
import java.util.Base64

/**
 * ML-KEM-768 + HKDF-SHA-512 implementation of [CryptoKeyServicePort].
 *
 * Holds up to two [MlKemService] instances:
 * - [currentService] — the active KEK used for [generateDek], [wrapDek],
 *   [rewrapDekForNewKek], [generateNewKekPair] and [getPublicKeyFingerprint]. Loaded from
 *   `ML_KEM_PUBLIC_KEY_CURRENT` / `ML_KEM_PRIVATE_KEY_CURRENT`.
 * - [legacyService] — read-only KEK used **only** by [unwrapDek] when the wrapped DEK is
 *   tagged with [MlKemService.WRAP_ALGORITHM_LEGACY_V0]. Loaded from
 *   `ML_KEM_PUBLIC_KEY_LEGACY_V0` / `ML_KEM_PRIVATE_KEY_LEGACY_V0`. Material that originally
 *   shipped under the unsuffixed `ML_KEM_*` env vars must be re-bound to the LEGACY_V0
 *   names before this service can read it.
 *
 * This separation enforces the operator constraint "the legacy KEK is used for unwrapping
 * legacy data only, never for new wraps." Calls that would mint or rewrap material under
 * the legacy KEK will fail loudly when [currentService] is null.
 *
 * This is the sole class in this module that may reference [MlKemService] directly;
 * enforced by `CryptoBoundaryArchTest` rule S-3.
 *
 * TEMPORARY (legacy-rewrap-cleanup, LRW-01): after all monolith DEKs are rewrapped under
 * the current KEK, collapse this class back to a single-service constructor and remove
 * the legacy dispatch in [unwrapDek]. Tracked in
 * `meta-project/work-items/phases/phase14/items.md` § "Legacy-DEK rewrap follow-up".
 */
class MlKemCryptoKeyService(
    private val currentService: MlKemService?,
    private val legacyService: MlKemService? = null,
) : CryptoKeyServicePort {
    override val isAvailable: Boolean = currentService != null || legacyService != null

    /** True when the current KEK is configured (= /v1/dek/{generate,wrap,rewrap,key-status} can serve). */
    val hasCurrentKek: Boolean = currentService != null

    /** True when the legacy KEK is configured (= legacy-tagged /v1/dek/unwrap can serve). */
    val hasLegacyKek: Boolean = legacyService != null

    override suspend fun generateDek(): CryptoKeyServicePort.GeneratedDek {
        val svc = requireCurrent("generateDek")
        val out = svc.generateAndWrapDek()
        return CryptoKeyServicePort.GeneratedDek(
            wrapped =
                WrappedDek(
                    kemCiphertextB64 = out.kemCiphertextB64,
                    encryptedDekB64 = out.encryptedDekB64,
                    algorithm = MlKemService.WRAP_ALGORITHM_CURRENT,
                ),
            plaintextBytes = out.plaintextDek,
        )
    }

    override suspend fun wrapDek(dekBytes: ByteArray): WrappedDek {
        val svc = requireCurrent("wrapDek")
        val (kemB64, encB64) = svc.wrapDek(dekBytes)
        return WrappedDek(
            kemCiphertextB64 = kemB64,
            encryptedDekB64 = encB64,
            algorithm = MlKemService.WRAP_ALGORITHM_CURRENT,
        )
    }

    override suspend fun unwrapDek(wrapped: WrappedDek): ByteArray =
        when (wrapped.algorithm) {
            MlKemService.WRAP_ALGORITHM_LEGACY_V0 -> {
                val svc =
                    legacyService
                        ?: error(
                            "Legacy KEK not configured: cannot unwrap DEK tagged " +
                                "${MlKemService.WRAP_ALGORITHM_LEGACY_V0}. Set " +
                                "ML_KEM_PUBLIC_KEY_LEGACY_V0 + ML_KEM_PRIVATE_KEY_LEGACY_V0 " +
                                "in security-service/.env.",
                        )
                svc.decapsulateAndUnwrapDekLegacy(wrapped.kemCiphertextB64, wrapped.encryptedDekB64)
            }
            else -> {
                val svc = requireCurrent("unwrapDek(${wrapped.algorithm})")
                svc.decapsulateAndUnwrapDek(wrapped.kemCiphertextB64, wrapped.encryptedDekB64)
            }
        }

    override suspend fun rewrapDekForNewKek(
        existingWrapped: WrappedDek,
        newPublicKeyBytes: ByteArray,
    ): WrappedDek {
        // Unwrap goes through the algorithm-aware dispatch so legacy DEKs can be migrated.
        val dekBytes = unwrapDek(existingWrapped)
        return try {
            val (newKemB64, newEncDekB64) = MlKemService.wrapDekForPublicKey(dekBytes, newPublicKeyBytes)
            WrappedDek(
                kemCiphertextB64 = newKemB64,
                encryptedDekB64 = newEncDekB64,
                algorithm = MlKemService.WRAP_ALGORITHM_CURRENT,
            )
        } finally {
            dekBytes.fill(0)
        }
    }

    override fun generateNewKekPair(): KekPair {
        requireCurrent("generateNewKekPair")
        val (pub, priv) = MlKemService.generateKeyPair()
        return KekPair(publicKeyB64 = pub, privateKeyB64 = priv)
    }

    override fun getPublicKeyFingerprint(): String = requireCurrent("getPublicKeyFingerprint").getPublicKeyFingerprint()

    private fun requireCurrent(operation: String): MlKemService =
        currentService
            ?: error(
                "Current KEK not configured: cannot perform '$operation'. Set " +
                    "ML_KEM_PUBLIC_KEY_CURRENT + ML_KEM_PRIVATE_KEY_CURRENT in security-service/.env. " +
                    "The legacy KEK (LEGACY_V0) is unwrap-only and must not be used to mint new DEKs.",
            )

    /** True when the operator has bound material to the deprecated unsuffixed ML_KEM_* env vars. */
    fun hasUnsuffixedEnvVars(): Boolean = unsuffixedEnvVarsPresent()

    companion object {
        /**
         * Construct from env vars. Reads up to two ML-KEM keypairs:
         *
         *  - `ML_KEM_PUBLIC_KEY_CURRENT` + `ML_KEM_PRIVATE_KEY_CURRENT` → current KEK
         *  - `ML_KEM_PUBLIC_KEY_LEGACY_V0` + `ML_KEM_PRIVATE_KEY_LEGACY_V0` → legacy KEK
         *
         * Unsuffixed `ML_KEM_PUBLIC_KEY` / `ML_KEM_PRIVATE_KEY` are IGNORED — operators must
         * rebind material to one of the suffixed pairs (the security-service DI module
         * surfaces a startup warning when the unsuffixed vars are still set).
         *
         * Returns null when neither suffixed pair is present.
         */
        fun fromEnv(): MlKemCryptoKeyService? {
            val current = MlKemService.fromCurrentEnv()
            val legacy = MlKemService.fromLegacyEnv()
            if (current == null && legacy == null) return null
            return MlKemCryptoKeyService(currentService = current, legacyService = legacy)
        }

        fun unsuffixedEnvVarsPresent(): Boolean =
            !System.getenv("ML_KEM_PUBLIC_KEY").isNullOrBlank() ||
                !System.getenv("ML_KEM_PRIVATE_KEY").isNullOrBlank()

        /**
         * Bootstrap helper: generate a fresh ML-KEM-768 keypair without requiring an
         * already-loaded current KEK. The result is suitable for first-time provisioning
         * via the `generate-kek` CLI; for in-band rotation use the live
         * [generateNewKekPair] instance method via `POST /v1/admin/rotate-kek` (which
         * delegates to the same underlying generator but is gated by mTLS + audit).
         */
        fun generateBootstrapKekPair(): com.shared.security.application.ports.KekPair {
            val (pub, priv) = MlKemService.generateKeyPair()
            return com.shared.security.application.ports.KekPair(publicKeyB64 = pub, privateKeyB64 = priv)
        }

        /** Construct from raw key bytes for the current KEK only. Test-helper. */
        fun fromBytes(
            publicKeyBytes: ByteArray,
            privateKeyBytes: ByteArray,
        ): MlKemCryptoKeyService = MlKemCryptoKeyService(currentService = MlKemService(publicKeyBytes, privateKeyBytes))

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
