package com.shared.security.adapters.outbound.jwtsigning

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * SKS-K04 / SKS-K04b — ECDSA P-256 (ES256) signing primitive for Stream K. Lives in the
 * dedicated `adapters/outbound/jwt-signing/` submodule per the v0.2 amendment so JWT
 * signing primitives never collocate with the KEK/DEK crypto module.
 *
 * **Responsibilities:** generate fresh ES256 keypairs (for new STAGED rows in
 * `jwt_signing_keys`), sign byte sequences against a stored private key, and derive
 * SPKI public-key bytes for JWKS publication. Stateless; no key storage.
 *
 * **Key format:** private bytes are PKCS#8 DER (the standard private-key serialization
 * for the JCA `PrivateKey` interface); public bytes are X.509 SubjectPublicKeyInfo DER
 * (the standard public-key serialization that maps directly to JWK). Both are
 * algorithm-tagged so a `KeyFactory.getInstance("EC")` round-trips cleanly.
 *
 * **Signature format:** JWS-compatible "raw" R || S (two 32-byte big-endian integers
 * concatenated, total 64 bytes), NOT the ASN.1 DER format the JDK produces by default.
 * RFC 7518 §3.4 requires the raw form for ES256.
 *
 * **Defensive zeroization:** the in-process `PrivateKey` materializes the private bytes
 * inside the JCA — the caller hands us bytes that we zero immediately after the JCA
 * object is constructed. The JCA's internal key material lives for the duration of the
 * sign call; we have no portable way to zero it. This is the same trade-off the Kek
 * service makes.
 */
class Es256SigningService {
    init {
        // Bouncy Castle for the ECDSA implementation. Idempotent — Security.addProvider
        // returns -1 if already registered.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /** Generate a fresh P-256 keypair using the BouncyCastle provider. */
    fun generateKeyPair(): EcKeyPair {
        val gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        gen.initialize(java.security.spec.ECGenParameterSpec("secp256r1"), SecureRandom())
        val kp: KeyPair = gen.generateKeyPair()
        return EcKeyPair(
            privateKeyPkcs8 = kp.private.encoded,
            publicKeySpki = kp.public.encoded,
        )
    }

    /**
     * Sign [payload] using the private key reconstituted from [privateKeyPkcs8].
     * Returns the raw JWS-format ECDSA signature (R || S, 64 bytes).
     *
     * Zeroizes the input [privateKeyPkcs8] after the JCA `PrivateKey` is built, in a
     * finally block that runs whether sign succeeds or throws.
     */
    fun sign(
        privateKeyPkcs8: ByteArray,
        payload: ByteArray,
    ): ByteArray {
        val privateKey = decodePrivateKey(privateKeyPkcs8)
        try {
            val signer = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME)
            signer.initSign(privateKey)
            signer.update(payload)
            val derSig = signer.sign()
            return derToRaw(derSig)
        } finally {
            privateKeyPkcs8.fill(0)
        }
    }

    /**
     * Verify [signature] (raw JWS format, 64 bytes) against [payload] using
     * [publicKeySpki]. Used by [Es256SigningService] itself for round-trip probe tests
     * (see HSM ceremony §5.2 probe); production verification happens in the consuming
     * service via the shared client's `LocalJwksVerifierAdapter`.
     */
    fun verify(
        publicKeySpki: ByteArray,
        payload: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val publicKey = decodePublicKey(publicKeySpki)
        val verifier = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME)
        verifier.initVerify(publicKey)
        verifier.update(payload)
        return runCatching { verifier.verify(rawToDer(signature)) }.getOrDefault(false)
    }

    /**
     * Compute the JWS `kid` for a public key. Format: lowercase hex of SHA-256(SPKI)
     * truncated to the first 16 bytes (32 hex chars). Stable across processes; safe to
     * persist as the `kid` PRIMARY KEY in `jwt_signing_keys`.
     */
    fun computeKid(publicKeySpki: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKeySpki)
        return digest.copyOfRange(0, 16)
    }

    /**
     * Convert an X.509 SPKI public key into the JWK form required by RFC 7517 ES256:
     * `{"kty":"EC","crv":"P-256","x":"<base64url>","y":"<base64url>"}`. The caller adds
     * the `kid`, `use`, `alg` fields.
     */
    fun spkiToJwkXY(publicKeySpki: ByteArray): JwkXY {
        val publicKey = decodePublicKey(publicKeySpki) as java.security.interfaces.ECPublicKey
        val point = publicKey.w
        val xBytes = bigIntegerToFixedBytes(point.affineX, COORD_BYTES)
        val yBytes = bigIntegerToFixedBytes(point.affineY, COORD_BYTES)
        val enc = Base64.getUrlEncoder().withoutPadding()
        return JwkXY(x = enc.encodeToString(xBytes), y = enc.encodeToString(yBytes))
    }

    private fun decodePrivateKey(pkcs8: ByteArray): PrivateKey {
        val factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        return factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
    }

    private fun decodePublicKey(spki: ByteArray): PublicKey {
        val factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        return factory.generatePublic(X509EncodedKeySpec(spki))
    }

    /**
     * Convert a DER-encoded ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` into the
     * raw R || S form required by JWS ES256. Both R and S are padded/truncated to
     * exactly 32 bytes.
     */
    private fun derToRaw(der: ByteArray): ByteArray {
        // Minimal ASN.1 parser specific to the SEQUENCE { INTEGER, INTEGER } DER form.
        require(der[0] == 0x30.toByte()) { "Malformed ECDSA DER: missing SEQUENCE tag" }
        var idx = 2
        if (der[1] == 0x81.toByte()) idx = 3 // long-form length prefix
        require(der[idx] == 0x02.toByte()) { "Malformed ECDSA DER: missing first INTEGER tag" }
        val rLen = der[idx + 1].toInt() and 0xFF
        val r = der.copyOfRange(idx + 2, idx + 2 + rLen)
        idx += 2 + rLen
        require(der[idx] == 0x02.toByte()) { "Malformed ECDSA DER: missing second INTEGER tag" }
        val sLen = der[idx + 1].toInt() and 0xFF
        val s = der.copyOfRange(idx + 2, idx + 2 + sLen)
        return bigIntegerToFixedBytes(BigInteger(1, r), COORD_BYTES) +
            bigIntegerToFixedBytes(BigInteger(1, s), COORD_BYTES)
    }

    /**
     * Reverse of [derToRaw]: pack raw R || S back into DER for the JCA verifier. This
     * is only used by the verify probe (not on the production sign path).
     */
    private fun rawToDer(raw: ByteArray): ByteArray {
        require(raw.size == COORD_BYTES * 2) { "Raw ECDSA signature must be ${COORD_BYTES * 2} bytes" }
        val r = BigInteger(1, raw.copyOfRange(0, COORD_BYTES))
        val s = BigInteger(1, raw.copyOfRange(COORD_BYTES, COORD_BYTES * 2))
        val rBytes = r.toByteArray()
        val sBytes = s.toByteArray()
        val totalLen = 2 + rBytes.size + 2 + sBytes.size
        val der = ByteArray(2 + totalLen)
        der[0] = 0x30
        der[1] = totalLen.toByte()
        der[2] = 0x02
        der[3] = rBytes.size.toByte()
        System.arraycopy(rBytes, 0, der, 4, rBytes.size)
        der[4 + rBytes.size] = 0x02
        der[4 + rBytes.size + 1] = sBytes.size.toByte()
        System.arraycopy(sBytes, 0, der, 4 + rBytes.size + 2, sBytes.size)
        return der
    }

    private fun bigIntegerToFixedBytes(
        value: BigInteger,
        length: Int,
    ): ByteArray {
        val raw = value.toByteArray()
        return when {
            raw.size == length -> raw
            raw.size == length + 1 && raw[0] == 0.toByte() -> raw.copyOfRange(1, raw.size)
            raw.size < length -> ByteArray(length - raw.size) + raw
            else -> error("Integer too large for $length bytes (got ${raw.size})")
        }
    }

    private companion object {
        const val COORD_BYTES = 32
    }
}

/** ES256 keypair, both halves serialized in their standard JCA form. */
data class EcKeyPair(
    val privateKeyPkcs8: ByteArray,
    val publicKeySpki: ByteArray,
) {
    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}

/** JWK x/y affine coordinates, base64url-encoded per RFC 7517. */
data class JwkXY(
    val x: String,
    val y: String,
)
