package com.shared.security.application.usecases.blindindex

import com.shared.security.application.ports.FinancialDedupHmacKeyRecord
import com.shared.security.application.ports.FinancialDedupHmacKeyRepository
import com.shared.security.application.ports.KekEnvelopePort
import com.shared.security.application.ports.WrappedBlob
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference

class ComputeFinancialDedupBlindIndexUseCaseTest {
    // In-memory KEK envelope: wrap stores the plaintext b64, unwrap returns it. Good enough
    // to assert the key-lifecycle + HMAC behavior without real ML-KEM.
    private class FakeKekEnvelope : KekEnvelopePort {
        var wrapCount = 0

        override suspend fun wrap(
            plaintext: ByteArray,
            aad: ByteArray,
        ): WrappedBlob {
            wrapCount++
            return WrappedBlob(
                kemCiphertextB64 = "kem",
                encryptedBytesB64 = java.util.Base64.getEncoder().encodeToString(plaintext),
                algorithm = "test",
                kekId = "kek-1",
            )
        }

        override suspend fun unwrap(
            wrapped: WrappedBlob,
            aad: ByteArray,
        ): ByteArray = java.util.Base64.getDecoder().decode(wrapped.encryptedBytesB64)
    }

    private class InMemoryRepo : FinancialDedupHmacKeyRepository {
        private val ref = AtomicReference<FinancialDedupHmacKeyRecord?>(null)

        override suspend fun findActive(): FinancialDedupHmacKeyRecord? = ref.get()

        override suspend fun insertActive(record: FinancialDedupHmacKeyRecord): Boolean {
            return ref.compareAndSet(null, record)
        }
    }

    private fun prehash(preimage: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(preimage.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun `same prehash yields same index across calls`() =
        runTest {
            val uc = ComputeFinancialDedupBlindIndexUseCase(InMemoryRepo(), FakeKekEnvelope())
            val a = uc.compute(prehash("acct|2026-01-15|-450|coffeeshop|0"))
            val b = uc.compute(prehash("acct|2026-01-15|-450|coffeeshop|0"))
            assertArrayEquals(a, b)
        }

    @Test
    fun `different prehash yields different index`() =
        runTest {
            val uc = ComputeFinancialDedupBlindIndexUseCase(InMemoryRepo(), FakeKekEnvelope())
            val a = uc.compute(prehash("acct|2026-01-15|-450|coffeeshop|0"))
            val b = uc.compute(prehash("acct|2026-01-15|-550|coffeeshop|0"))
            assertFalse(a.contentEquals(b))
        }

    @Test
    fun `output is 32 bytes`() =
        runTest {
            val uc = ComputeFinancialDedupBlindIndexUseCase(InMemoryRepo(), FakeKekEnvelope())
            assertEquals(32, uc.compute(prehash("x")).size)
        }

    @Test
    fun `rejects a prehash that is not 32 bytes`() =
        runTest {
            val uc = ComputeFinancialDedupBlindIndexUseCase(InMemoryRepo(), FakeKekEnvelope())
            assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking { uc.compute(ByteArray(16)) }
            }
        }

    @Test
    fun `key is generated once and cached`() =
        runTest {
            val envelope = FakeKekEnvelope()
            val uc = ComputeFinancialDedupBlindIndexUseCase(InMemoryRepo(), envelope)
            uc.compute(prehash("a"))
            uc.compute(prehash("b"))
            assertEquals(1, envelope.wrapCount)
        }
}
