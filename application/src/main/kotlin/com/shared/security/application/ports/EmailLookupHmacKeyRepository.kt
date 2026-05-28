package com.shared.security.application.ports

import kotlinx.datetime.Instant

/**
 * Persistence port for the single ACTIVE email-lookup HMAC key. The key material is stored
 * KEK-wrapped (see [KekEnvelopePort]); this port deals only in the wrapped envelope bytes.
 */
interface EmailLookupHmacKeyRepository {
    /** The current ACTIVE key, or null if none has been generated yet. */
    suspend fun findActive(): EmailLookupHmacKeyRecord?

    /**
     * Insert [record] as the ACTIVE key. Returns true on success; returns false when a
     * concurrent caller already inserted the singleton ACTIVE row (the unique-index race
     * loser re-reads via [findActive]).
     */
    suspend fun insertActive(record: EmailLookupHmacKeyRecord): Boolean
}

data class EmailLookupHmacKeyRecord(
    val id: String,
    val version: Int,
    /** KEK-wrapped HMAC key, encoded by `WrappedBlobCodec`. */
    val wrappedKeyBytes: ByteArray,
    val wrappedUnderKekId: String,
    val createdAt: Instant,
) {
    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}
