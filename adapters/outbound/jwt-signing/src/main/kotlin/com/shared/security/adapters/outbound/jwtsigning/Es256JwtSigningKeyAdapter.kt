package com.shared.security.adapters.outbound.jwtsigning

import com.shared.security.application.usecases.jwt.GeneratedKeyPair
import com.shared.security.application.usecases.jwt.JwkCoords
import com.shared.security.application.usecases.jwt.JwtSigningKeyPort

/**
 * Adapter binding the application-layer [JwtSigningKeyPort] to the concrete
 * [Es256SigningService] primitive in this submodule. Pure delegation — exists so the
 * application module never imports a class from `adapters/outbound/jwt-signing/`
 * (enforced by ArchUnit rule S-12).
 */
class Es256JwtSigningKeyAdapter(
    private val service: Es256SigningService = Es256SigningService(),
) : JwtSigningKeyPort {
    override fun generateKeyPair(): GeneratedKeyPair {
        val ec = service.generateKeyPair()
        return GeneratedKeyPair(privateKeyPkcs8 = ec.privateKeyPkcs8, publicKeySpki = ec.publicKeySpki)
    }

    override fun sign(
        privateKeyPkcs8: ByteArray,
        payload: ByteArray,
    ): ByteArray = service.sign(privateKeyPkcs8, payload)

    override fun verify(
        publicKeySpki: ByteArray,
        payload: ByteArray,
        signature: ByteArray,
    ): Boolean = service.verify(publicKeySpki, payload, signature)

    override fun computeKid(publicKeySpki: ByteArray): ByteArray = service.computeKid(publicKeySpki)

    override fun spkiToJwkXY(publicKeySpki: ByteArray): JwkCoords {
        val coords = service.spkiToJwkXY(publicKeySpki)
        return JwkCoords(x = coords.x, y = coords.y)
    }
}
