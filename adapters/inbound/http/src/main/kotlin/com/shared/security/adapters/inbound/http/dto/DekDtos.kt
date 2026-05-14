package com.shared.security.adapters.inbound.http.dto

import kotlinx.serialization.Serializable

/**
 * Wire shape for a wrapped DEK envelope. All fields are plain strings (base64) so the
 * contract is trivially portable across languages and HTTP clients.
 */
@Serializable
data class WrappedDekDto(
    val kemCiphertextB64: String,
    val encryptedDekB64: String,
    val algorithm: String = "ML-KEM-768/AES-256-GCM",
)

@Serializable
data class GenerateDekResponse(
    /** Wrapped DEK to persist in the calling service's DB. */
    val wrapped: WrappedDekDto,
    /**
     * Plaintext DEK bytes, base64-encoded. The caller MUST use these immediately and
     * MUST NOT persist them. Returned only to avoid a round-trip generate+unwrap.
     */
    val plaintextDekB64: String,
)

@Serializable
data class WrapDekRequest(
    /** Plaintext DEK bytes, base64-encoded. Must decode to exactly 32 bytes. */
    val dekBytesB64: String,
)

@Serializable
data class WrapDekResponse(val wrapped: WrappedDekDto)

@Serializable
data class UnwrapDekRequest(val wrapped: WrappedDekDto)

@Serializable
data class UnwrapDekResponse(
    /** Plaintext DEK bytes, base64-encoded. See [GenerateDekResponse.plaintextDekB64] for caller contract. */
    val plaintextDekB64: String,
)

@Serializable
data class RewrapDekRequest(
    val existing: WrappedDekDto,
    /** Target KEK public key, base64-encoded. */
    val newPublicKeyB64: String,
)

@Serializable
data class RewrapDekResponse(val wrapped: WrappedDekDto)

@Serializable
data class ErrorResponse(val error: String, val detail: String? = null)
