package com.shared.security.application.usecases.blindindex

import com.shared.security.application.ports.EmailLookupHmacKeyRecord
import com.shared.security.application.ports.EmailLookupHmacKeyRepository
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
 * Computes the 16-byte email blind index for a caller-supplied plaintext email. The HMAC
 * key never leaves the security service: callers send a normalized email and receive only
 * the truncated MAC.
 *
 * The key is generated on first use (32 random bytes, KEK-wrapped, persisted as the
 * singleton ACTIVE row). The unwrapped key is cached in memory for the JVM lifetime —
 * unwrapping on every request would put the KEK on the hot path of every monolith
 * findByEmail. A concurrent first-call race is resolved by the DB singleton constraint:
 * the insert loser re-reads and unwraps the winner's key.
 *
 * Normalization is `trim().lowercase()` — pinned by test. Plus-addressing is preserved
 * (`alice+work@x.com` and `alice@x.com` hash differently).
 */
class ComputeEmailBlindIndexUseCase(
    private val repo: EmailLookupHmacKeyRepository,
    private val kekEnvelope: KekEnvelopePort,
    private val clock: Clock = Clock.System,
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    @Volatile
    private var cachedKey: ByteArray? = null
    private val keyInitMutex = Mutex()

    suspend fun compute(email: String): ByteArray {
        val key = cachedKey ?: loadOrGenerateKey()
        val normalized = email.trim().lowercase().toByteArray(Charsets.UTF_8)
        val mac =
            Mac.getInstance(HMAC_ALGORITHM).apply {
                init(SecretKeySpec(key, HMAC_ALGORITHM))
            }
        return mac.doFinal(normalized).copyOfRange(0, BLIND_INDEX_BYTES)
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

    private suspend fun unwrap(record: EmailLookupHmacKeyRecord): ByteArray {
        val wrapped = WrappedBlobCodec.decode(record.wrappedKeyBytes)
        return kekEnvelope.unwrap(wrapped, aadFor(record.version))
    }

    private suspend fun generateAndPersist(): ByteArray {
        val keyBytes = ByteArray(HMAC_KEY_BYTES).also(secureRandom::nextBytes)
        // wrap() zeroizes its input; hand it a copy so we keep the bytes to cache + return.
        val wrapped = kekEnvelope.wrap(keyBytes.copyOf(), aadFor(VERSION_1))
        val record =
            EmailLookupHmacKeyRecord(
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
        val winner = repo.findActive() ?: error("ACTIVE email-lookup HMAC key vanished after insert race")
        return unwrap(winner)
    }

    private companion object {
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val HMAC_KEY_BYTES = 32
        private const val BLIND_INDEX_BYTES = 16
        private const val VERSION_1 = 1

        private fun aadFor(version: Int): ByteArray = "email-lookup-hmac-key:$version".toByteArray(Charsets.UTF_8)
    }
}
