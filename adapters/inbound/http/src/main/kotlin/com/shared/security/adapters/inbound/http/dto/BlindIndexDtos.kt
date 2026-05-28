package com.shared.security.adapters.inbound.http.dto

import kotlinx.serialization.Serializable

/**
 * Request for an email blind index. The plaintext email is normalized server-side
 * (`trim().lowercase()`) before hashing; the caller need not pre-normalize. The email
 * is never logged or persisted by the security service — only HMAC'd and discarded.
 */
@Serializable
data class EmailBlindIndexRequest(
    val email: String,
)

@Serializable
data class EmailBlindIndexResponse(
    /** 16-byte truncated HMAC-SHA-256 over the normalized email, base64-encoded. */
    val blindIndexB64: String,
)
