package com.shared.security.adapters.outbound.crypto

import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.KekLifecycleStatus
import com.shared.security.application.ports.KekRecord
import com.shared.security.application.ports.KekRepository
import com.shared.security.application.ports.WrappedDek
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * SKS-K01a — Validates the AAD-binding behaviour of [KekEnvelopeAdapter] (the v0.2
 * internal-port bridge). The underlying [CryptoKeyServicePort] is mocked with a fake
 * round-trip wrap so the tests exercise the AAD prefix/verify logic, not the real
 * ML-KEM crypto.
 */
class KekEnvelopeAdapterTest {
    private val fakeCryptoService =
        object : CryptoKeyServicePort {
            override val isAvailable = true

            override suspend fun generateDek(): CryptoKeyServicePort.GeneratedDek = error("not used in this test")

            override suspend fun wrapDek(dekBytes: ByteArray): WrappedDek =
                WrappedDek(
                    kemCiphertextB64 = java.util.Base64.getEncoder().encodeToString(dekBytes),
                    encryptedDekB64 = "fake-enc",
                    algorithm = "ML-KEM-768/AES-256-GCM",
                )

            override suspend fun unwrapDek(wrapped: WrappedDek): ByteArray {
                return java.util.Base64.getDecoder().decode(wrapped.kemCiphertextB64)
            }

            override suspend fun rewrapDekForNewKek(
                existingWrapped: WrappedDek,
                newPublicKeyBytes: ByteArray,
            ): WrappedDek = error("not used in this test")

            override fun generateNewKekPair() = error("not used in this test")

            override fun getPublicKeyFingerprint() = error("not used in this test")
        }

    private val fakeKekRepository =
        object : KekRepository {
            override suspend fun findActive(): KekRecord =
                KekRecord(
                    id = "fake-kek-id",
                    fingerprint = "00:11",
                    status = KekLifecycleStatus.ACTIVE,
                    createdAt = Clock.System.now(),
                    activatedAt = Clock.System.now(),
                    quiescedAt = null,
                    retiredAt = null,
                )

            override suspend fun findAllPrior() = emptyList<KekRecord>()

            override suspend fun findById(id: String) = null

            override suspend fun retirePrior(id: String) = false

            override suspend fun findAll() = emptyList<KekRecord>()
        }

    private val adapter = KekEnvelopeAdapter(fakeCryptoService, fakeKekRepository)

    @Test
    fun `wrap_unwrap roundtrips plaintext when AAD matches`() =
        runTest {
            val plaintext = "the-plaintext-bytes".encodeToByteArray()
            val aad = "jwt-signing-key:abc123".encodeToByteArray()

            val wrapped = adapter.wrap(plaintext.copyOf(), aad)
            val recovered = adapter.unwrap(wrapped, aad)

            assertArrayEquals(plaintext, recovered)
            assertEquals("fake-kek-id", wrapped.kekId)
            assertEquals("ML-KEM-768/AES-256-GCM", wrapped.algorithm)
        }

    @Test
    fun `unwrap fails on AAD mismatch`() =
        runTest {
            val plaintext = "the-plaintext-bytes".encodeToByteArray()
            val wrapAad = "jwt-signing-key:abc123".encodeToByteArray()
            val tamperedAad = "jwt-signing-key:def456".encodeToByteArray()

            val wrapped = adapter.wrap(plaintext.copyOf(), wrapAad)

            assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking { adapter.unwrap(wrapped, tamperedAad) }
            }
        }

    @Test
    fun `wrap rejects empty AAD`() =
        runTest {
            val plaintext = "x".encodeToByteArray()
            val emptyAad = ByteArray(0)

            assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking { adapter.wrap(plaintext, emptyAad) }
            }
        }

    @Test
    fun `wrap stamps kekId from the current ACTIVE KEK`() =
        runTest {
            val plaintext = "x".encodeToByteArray()
            val aad = "y".encodeToByteArray()

            val wrapped = adapter.wrap(plaintext, aad)

            assertEquals("fake-kek-id", wrapped.kekId)
        }
}
