package com.shared.security.adapters.inbound.http.dto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Wire shape for POST /v1/jwt/sign. The calling service supplies [subject], [audience],
 * [issuer], [expiresInSeconds], and an optional [extraClaims] map. The Gate-1 (mTLS) DN
 * is already known to the server from the request peer cert; the Gate-2 audience
 * allow-list check is done server-side against that DN.
 */
@Serializable
data class SignJwtRequestDto(
    val subject: String,
    val audience: String,
    val issuer: String,
    val expiresInSeconds: Long,
    val extraClaims: Map<String, JsonElement> = emptyMap(),
)

@Serializable
data class SignJwtResponseDto(
    /** Compact JWS serialization: `<header>.<payload>.<signature>` (all base64url). */
    val token: String,
    /** Hex-encoded `kid` of the signing key used; matches the JWS header `kid`. */
    val kidHex: String,
    /** Epoch seconds — the JWT's `exp` claim. */
    val expiresAt: Long,
)

/** RFC 7517 EC JWK. */
@Serializable
data class JwkDto(
    val kty: String = "EC",
    val crv: String = "P-256",
    val x: String,
    val y: String,
    val alg: String = "ES256",
    val use: String = "sig",
    val kid: String,
)

@Serializable
data class JwksResponseDto(val keys: List<JwkDto>)
