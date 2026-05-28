package com.shared.security.application.usecases.blindindex

import com.shared.security.application.ports.EmailLookupHmacKeyRecord
import com.shared.security.application.ports.EmailLookupHmacKeyRepository
import com.shared.security.application.ports.KekEnvelopePort
import com.shared.security.application.ports.WrappedBlob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.util.Base64

class ComputeEmailBlindIndexUseCaseTest {
    @Test
    fun `compute returns a 16-byte hash`() =
        runBlocking {
            val uc = ComputeEmailBlindIndexUseCase(InMemoryRepo(), IdentityKekEnvelope())
            assertEquals(16, uc.compute("alice@example.com").size)
        }

    @Test
    fun `same email produces the same hash`() =
        runBlocking {
            val uc = ComputeEmailBlindIndexUseCase(InMemoryRepo(), IdentityKekEnvelope())
            assertArrayEquals(uc.compute("alice@example.com"), uc.compute("alice@example.com"))
        }

    @Test
    fun `normalization — trim and lowercase produce the same hash`() =
        runBlocking {
            val uc = ComputeEmailBlindIndexUseCase(InMemoryRepo(), IdentityKekEnvelope())
            assertArrayEquals(
                uc.compute("alice@example.com"),
                uc.compute("  Alice@Example.COM  "),
            )
        }

    @Test
    fun `plus-addressing is preserved — different hash`() =
        runBlocking {
            val uc = ComputeEmailBlindIndexUseCase(InMemoryRepo(), IdentityKekEnvelope())
            assertFalse(
                uc.compute("alice+work@example.com").contentEquals(uc.compute("alice@example.com")),
            )
        }

    @Test
    fun `generates and persists the active key on first use`() =
        runBlocking {
            val repo = InMemoryRepo()
            assertNull(repo.findActive())
            ComputeEmailBlindIndexUseCase(repo, IdentityKekEnvelope()).compute("a@b.com")
            assertNotNull(repo.findActive())
        }

    @Test
    fun `a second instance loads the persisted key and matches`() =
        runBlocking {
            val repo = InMemoryRepo()
            val kek = IdentityKekEnvelope()
            val first = ComputeEmailBlindIndexUseCase(repo, kek).compute("alice@example.com")
            // New instance, same repo + KEK — must unwrap the persisted key, not generate a new one.
            val second = ComputeEmailBlindIndexUseCase(repo, kek).compute("alice@example.com")
            assertArrayEquals(first, second)
        }

    /** Identity wrap/unwrap — stores plaintext base64 in the envelope. Test double only. */
    private class IdentityKekEnvelope : KekEnvelopePort {
        override suspend fun wrap(
            plaintext: ByteArray,
            aad: ByteArray,
        ): WrappedBlob =
            WrappedBlob(
                kemCiphertextB64 = "",
                encryptedBytesB64 = Base64.getEncoder().encodeToString(plaintext),
                algorithm = "test-identity",
                kekId = "test-kek",
            )

        override suspend fun unwrap(
            wrapped: WrappedBlob,
            aad: ByteArray,
        ): ByteArray = Base64.getDecoder().decode(wrapped.encryptedBytesB64)
    }

    private class InMemoryRepo : EmailLookupHmacKeyRepository {
        private var active: EmailLookupHmacKeyRecord? = null

        override suspend fun findActive(): EmailLookupHmacKeyRecord? = active

        override suspend fun insertActive(record: EmailLookupHmacKeyRecord): Boolean {
            if (active != null) return false
            active = record
            return true
        }
    }
}
