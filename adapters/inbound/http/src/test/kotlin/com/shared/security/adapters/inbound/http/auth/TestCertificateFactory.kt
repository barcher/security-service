package com.shared.security.adapters.inbound.http.auth

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Generates ephemeral X.509 certs at test setup time. Uses ECDSA P-384 to match the prod
 * profile from proposal §7.2. Self-signed; no CA chain needed for unit tests that exercise
 * application-layer auth (the TLS engine that would validate against a CA is bypassed via
 * [TestPeerCertChainExtractor]).
 */
object TestCertificateFactory {
    init {
        // Idempotent: BouncyCastleProvider register is a no-op if already registered.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private const val SIGNATURE_ALG = "SHA384withECDSA"
    private const val CURVE = "secp384r1"
    private const val ONE_DAY_MILLIS = 24L * 60L * 60L * 1000L

    fun generate(subjectDn: String = "CN=test-client,O=WorkAutomations,L=Local"): X509Certificate {
        val kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        kpg.initialize(ECGenParameterSpec(CURVE), SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val now = System.currentTimeMillis()
        val notBefore = Date(now - ONE_DAY_MILLIS)
        val notAfter = Date(now + ONE_DAY_MILLIS)
        val serial = BigInteger.valueOf(now)

        val builder =
            JcaX509v3CertificateBuilder(
                X500Name(subjectDn),
                serial,
                notBefore,
                notAfter,
                X500Name(subjectDn),
                keyPair.public,
            )

        val signer =
            JcaContentSignerBuilder(SIGNATURE_ALG)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.private)
        val holder = builder.build(signer)

        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(holder)
    }
}
