package com.shared.security.application.ports

import kotlinx.datetime.Instant

/**
 * Read/write surface over `jwt_signing_keys` rows for the ES256 signing-key lifecycle
 * state machine (Stream K, proposal §8). Mirrors [KekRepository] in shape; differs in
 * that JWT keys' wrapped private bytes ARE persisted in this row (unlike KEK rows which
 * never hold key material).
 *
 * The port returns plain value types so application code is unaware of Exposed.
 */
interface JwtSigningKeyRepository {
    /** Currently ACTIVE signing key, or null when none. Schema guarantees at most one row. */
    suspend fun findActive(): JwtSigningKeyRecord?

    /** All keys in PRIOR or QUIESCED status, ordered oldest first. */
    suspend fun findAllPriorAndQuiesced(): List<JwtSigningKeyRecord>

    /** Look up by primary-key `kid`. */
    suspend fun findByKid(kid: ByteArray): JwtSigningKeyRecord?

    /** All keys currently published in JWKS — i.e. ACTIVE + PRIOR rows. Ordered ACTIVE first. */
    suspend fun findAllPublishable(): List<JwtSigningKeyRecord>

    /**
     * Insert a STAGED row. The wrapped-private-bytes envelope must already be produced
     * by `KekEnvelopePort` — this repository does NOT wrap on behalf of the caller.
     */
    suspend fun insertStaged(record: JwtSigningKeyRecord)

    /**
     * Atomically transition the named STAGED key to ACTIVE, and the existing ACTIVE
     * (if any) to PRIOR. Returns true if a transition happened; false if [kid] was not
     * STAGED. The DB enforces the singleton-ACTIVE invariant via the generated-column
     * unique index; a race where two callers attempt to activate two different STAGED
     * keys is resolved by exactly one succeeding.
     */
    suspend fun activate(
        kid: ByteArray,
        now: Instant,
    ): Boolean

    /** Transition [kid] from PRIOR to QUIESCED. Sets `quiesced_at = now`. */
    suspend fun quiescePrior(
        kid: ByteArray,
        now: Instant,
    ): Boolean

    /**
     * Transition [kid] from QUIESCED to RETIRED. Sets `retired_at = now` and
     * `retain_until = now + retentionDays`. After this, the key is not published in
     * JWKS and is eligible for deletion via [deleteRetired] once `retain_until` passes.
     */
    suspend fun retireQuiesced(
        kid: ByteArray,
        now: Instant,
        retentionDays: Long,
    ): Boolean

    /** Delete the row for a RETIRED key whose `retain_until` is in the past. */
    suspend fun deleteRetired(kid: ByteArray): Boolean

    /** All RETIRED keys whose `retain_until <= [now]`. Used by the retention sweep. */
    suspend fun findRetiredEligibleForDelete(now: Instant): List<JwtSigningKeyRecord>
}

/**
 * One row in the `jwt_signing_keys` table. Includes wrapped private bytes (unlike
 * [KekRecord] which never holds key material) because the JWT layer needs to fetch
 * + unwrap the private key on every sign call. The wrap is done through
 * [KekEnvelopePort] so callers never see the KEK directly.
 */
data class JwtSigningKeyRecord(
    val kid: ByteArray,
    val status: JwtSigningKeyStatus,
    val algorithm: String,
    val curve: String,
    val wrappedPrivateKeyBytes: ByteArray,
    val publicKeySpki: ByteArray,
    val wrappedUnderKekId: String,
    val createdAt: Instant,
    val activatedAt: Instant?,
    val quiescedAt: Instant?,
    val retiredAt: Instant?,
    val retainUntil: Instant?,
) {
    /** Identity-based equality — `equals` on raw ByteArray fields is treacherous. */
    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}

enum class JwtSigningKeyStatus {
    STAGED,
    ACTIVE,
    PRIOR,
    QUIESCED,
    RETIRED,
}
