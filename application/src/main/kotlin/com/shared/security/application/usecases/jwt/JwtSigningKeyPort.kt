package com.shared.security.application.usecases.jwt

/**
 * Application-layer abstraction over the ES256 primitive provided by the
 * `adapters/outbound/jwt-signing/` submodule. The use cases consume this port instead of
 * the concrete `Es256SigningService` so the application module stays free of any
 * adapter-module dependency (the JWT use cases live in `application/`, the primitive
 * lives in `adapters/outbound/jwt-signing/`, and DI wires the two together).
 *
 * **Note:** this port intentionally does NOT cover JWT envelope formatting (header +
 * claims + base64url packing). The use case in [SignJwtUseCase] builds the JWT bytes
 * directly so the primitive remains a thin, replaceable signing surface.
 */
interface JwtSigningKeyPort {
    /** Generate a fresh P-256 keypair (PKCS#8 private bytes + SPKI public bytes). */
    fun generateKeyPair(): GeneratedKeyPair

    /**
     * Sign [payload] with [privateKeyPkcs8] (the JWS signing input — header.payload). Returns
     * raw R || S (64 bytes) per RFC 7518 §3.4. Implementations zeroize [privateKeyPkcs8]
     * after the JCA key object is materialized.
     */
    fun sign(
        privateKeyPkcs8: ByteArray,
        payload: ByteArray,
    ): ByteArray

    /** Verify a raw R||S signature against [payload] using [publicKeySpki]. */
    fun verify(
        publicKeySpki: ByteArray,
        payload: ByteArray,
        signature: ByteArray,
    ): Boolean

    /**
     * Compute the stable `kid` for a public key. Format defined by the implementation;
     * the resulting bytes are persisted as the `jwt_signing_keys` primary key and
     * surfaced in the JWS header.
     */
    fun computeKid(publicKeySpki: ByteArray): ByteArray

    /**
     * Project an SPKI public key into its JWK `x` and `y` base64url coordinates for
     * RFC 7517 publication.
     */
    fun spkiToJwkXY(publicKeySpki: ByteArray): JwkCoords
}

data class GeneratedKeyPair(
    val privateKeyPkcs8: ByteArray,
    val publicKeySpki: ByteArray,
) {
    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}

data class JwkCoords(
    val x: String,
    val y: String,
)
