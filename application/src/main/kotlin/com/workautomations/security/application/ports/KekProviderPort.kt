package com.workautomations.security.application.ports

/**
 * Source of KEK key material for the security service.
 *
 * Implementations decide where the bytes come from (a mounted secret directory in prod,
 * a env var in local dev, a hardware-backed secret store in regulated deployments). The
 * port returns plain bytes so that downstream callers do not need to know the storage form.
 *
 * Fail-closed contract: `loadKekMaterial()` MUST throw [KekUnavailableException] when key
 * material is missing or unreadable. The service refuses to start in that case (proposal
 * §8.5 disaster-recovery posture).
 */
interface KekProviderPort {
    data class KekMaterial(
        /** Base64-encoded ML-KEM-768 public key (1184 raw bytes → 1580 base64 chars). */
        val publicKeyB64: String,
        /** Base64-encoded ML-KEM-768 private key (2400 raw bytes → 3204 base64 chars). */
        val privateKeyB64: String,
    )

    /**
     * Load the active KEK material. Throws on missing or unreadable material; never returns
     * partial data. The service's bootstrap should call this exactly once at startup; rotation
     * is handled separately via `CryptoKeyServicePort.generateNewKekPair()`.
     */
    @Throws(KekUnavailableException::class)
    fun loadKekMaterial(): KekMaterial
}

/** Raised by [KekProviderPort] implementations on missing or corrupt material. Fail-closed. */
class KekUnavailableException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
