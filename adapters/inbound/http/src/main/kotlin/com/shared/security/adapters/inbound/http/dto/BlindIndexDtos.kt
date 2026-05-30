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

/**
 * Request for a financial-dedup blind index. Unlike the email route, the caller sends a
 * 32-byte SHA-256 PREHASH of the natural-key preimage (base64) — NOT the raw value. The
 * preimage folds in the transaction's merchant token, which is encrypted at rest, so the raw
 * value must never reach the security service. The service HMACs the prehash and discards it;
 * nothing is logged or persisted.
 */
@Serializable
data class FinancialDedupBlindIndexRequest(
    /** Base64 of the caller's 32-byte SHA-256 digest of the natural-key preimage. */
    val prehashB64: String,
)

@Serializable
data class FinancialDedupBlindIndexResponse(
    /** 32-byte HMAC-SHA-256 over the prehash, base64-encoded. */
    val blindIndexB64: String,
)
