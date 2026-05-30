package com.shared.security.application.usecases.blindindex

import com.shared.security.application.ports.FinancialDedupHmacKeyRecord
import com.shared.security.application.ports.FinancialDedupHmacKeyRepository
import com.shared.security.application.ports.KekEnvelopePort
import com.shared.security.application.usecases.jwt.WrappedBlobCodec
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Computes the financial-dedup blind index for a caller-supplied 32-byte SHA-256 PREHASH.
 * The HMAC key never leaves the security service.
 *
 * **Why a prehash (and not the raw value, unlike the email blind index).**
 * The email blind index accepts the plaintext email because an email address is not
 * encrypted-at-rest in a way that the index would compromise. The financial dedup preimage,
 * by contrast, folds in the transaction's merchant token — which IS encrypted at rest in
 * `financial_transactions.merchant_name_encrypted`. Sending the raw merchant to the security
 * service would defeat that encryption boundary. So financial-service computes a local
 * SHA-256 over the full natural-key preimage and sends only the resulting 32-byte digest;
 * the security service returns `HMAC-SHA-256(key, prehash)`. The merchant never crosses the
 * wire and the security service never sees it.
 *
 * The key is generated on first use (32 random bytes, KEK-wrapped, persisted as the
 * singleton ACTIVE row) and cached in memory for the JVM lifetime — unwrapping on every
 * request would put the KEK on the hot path of every transaction import. A concurrent
 * first-call race is resolved by the DB singleton constraint: the insert loser re-reads and
 * unwraps the winner's key.
 *
 * Output is the FULL 32-byte HMAC-SHA-256 (not truncated) — it fits the existing
 * `CHAR(64)` hex `dedup_hash` column and a wider index lowers collision probability for a
 * uniqueness-bearing column.
 */
class ComputeFinancialDedupBlindIndexUseCase(
    private val repo: FinancialDedupHmacKeyRepository,
    private val kekEnvelope: KekEnvelopePort,
    private val clock: Clock = Clock.System,
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    @Volatile
    private var cachedKey: ByteArray? = null
    private val keyInitMutex = Mutex()

    /**
     * @param prehash the caller's 32-byte SHA-256 digest of the natural-key preimage.
     * @return the 32-byte HMAC-SHA-256 over [prehash] under the ACTIVE dedup key.
     * @throws IllegalArgumentException if [prehash] is not exactly [PREHASH_BYTES] bytes.
     */
    suspend fun compute(prehash: ByteArray): ByteArray {
        require(prehash.size == PREHASH_BYTES) {
            "financial-dedup prehash must be $PREHASH_BYTES bytes (SHA-256), got ${prehash.size}"
        }
        val key = cachedKey ?: loadOrGenerateKey()
        val mac =
            Mac.getInstance(HMAC_ALGORITHM).apply {
                init(SecretKeySpec(key, HMAC_ALGORITHM))
            }
        return mac.doFinal(prehash)
    }

    private suspend fun loadOrGenerateKey(): ByteArray =
        keyInitMutex.withLock {
            // Double-checked: another coroutine may have populated the cache while we waited.
            cachedKey?.let { return it }
            val existing = repo.findActive()
            val unwrapped =
                if (existing != null) {
                    unwrap(existing)
                } else {
                    generateAndPersist()
                }
            cachedKey = unwrapped
            unwrapped
        }

    private suspend fun unwrap(record: FinancialDedupHmacKeyRecord): ByteArray {
        val wrapped = WrappedBlobCodec.decode(record.wrappedKeyBytes)
        return kekEnvelope.unwrap(wrapped, aadFor(record.version))
    }

    private suspend fun generateAndPersist(): ByteArray {
        val keyBytes = ByteArray(HMAC_KEY_BYTES).also(secureRandom::nextBytes)
        // wrap() zeroizes its input; hand it a copy so we keep the bytes to cache + return.
        val wrapped = kekEnvelope.wrap(keyBytes.copyOf(), aadFor(VERSION_1))
        val record =
            FinancialDedupHmacKeyRecord(
                id = UUID.randomUUID().toString(),
                version = VERSION_1,
                wrappedKeyBytes = WrappedBlobCodec.encode(wrapped),
                wrappedUnderKekId = wrapped.kekId,
                createdAt = clock.now(),
            )
        val inserted = repo.insertActive(record)
        if (inserted) return keyBytes
        // Lost the singleton race — zeroize our generated key and adopt the winner's.
        keyBytes.fill(0)
        val winner = repo.findActive() ?: error("ACTIVE financial-dedup HMAC key vanished after insert race")
        return unwrap(winner)
    }

    private companion object {
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val HMAC_KEY_BYTES = 32
        private const val PREHASH_BYTES = 32
        private const val VERSION_1 = 1

        private fun aadFor(version: Int): ByteArray = "financial-dedup-hmac-key:$version".toByteArray(Charsets.UTF_8)
    }
}
