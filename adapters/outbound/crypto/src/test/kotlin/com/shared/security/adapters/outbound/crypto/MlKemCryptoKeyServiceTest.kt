package com.shared.security.adapters.outbound.crypto

import com.shared.security.application.ports.WrappedDek
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle

@TestInstance(Lifecycle.PER_CLASS)
class MlKemCryptoKeyServiceTest {
    private lateinit var service: MlKemCryptoKeyService
    private lateinit var publicKeyBytes: ByteArray
    private lateinit var privateKeyBytes: ByteArray

    @BeforeAll
    fun setUp() {
        val (pubB64, privB64) = MlKemService.generateKeyPair()
        publicKeyBytes = java.util.Base64.getDecoder().decode(pubB64)
        privateKeyBytes = java.util.Base64.getDecoder().decode(privB64)
        service = MlKemCryptoKeyService.fromBytes(publicKeyBytes, privateKeyBytes)
    }

    @Test
    fun `generateDek produces a wrapped DEK that round-trips through unwrapDek`() =
        runTest {
            val generated = service.generateDek()

            val plaintext = service.unwrapDek(generated.wrapped)

            assertEquals(MlKemService.DEK_BYTES, generated.plaintextBytes.size)
            assertEquals(MlKemService.DEK_BYTES, plaintext.size)
            assertTrue(plaintext.contentEquals(generated.plaintextBytes))
        }

    @Test
    fun `wrapDek then unwrapDek recovers original bytes`() =
        runTest {
            val original = ByteArray(MlKemService.DEK_BYTES) { it.toByte() }

            val wrapped = service.wrapDek(original)
            val recovered = service.unwrapDek(wrapped)

            assertTrue(recovered.contentEquals(original))
        }

    @Test
    fun `each generateDek call produces a unique wrapped DEK`() =
        runTest {
            val a = service.generateDek()
            val b = service.generateDek()

            assertNotEquals(a.wrapped.kemCiphertextB64, b.wrapped.kemCiphertextB64)
            assertNotEquals(a.wrapped.encryptedDekB64, b.wrapped.encryptedDekB64)
            assertFalse(a.plaintextBytes.contentEquals(b.plaintextBytes))
        }

    @Test
    fun `rewrapDekForNewKek lets a new private key unwrap the same DEK material`() =
        runTest {
            val original = service.generateDek()
            val (newPubB64, newPrivB64) = MlKemService.generateKeyPair()
            val newPubBytes = java.util.Base64.getDecoder().decode(newPubB64)

            val rewrapped = service.rewrapDekForNewKek(original.wrapped, newPubBytes)

            val newService = MlKemCryptoKeyService.fromBase64(newPubB64, newPrivB64)
            val recovered = newService.unwrapDek(rewrapped)

            assertTrue(recovered.contentEquals(original.plaintextBytes))
        }

    @Test
    fun `unwrapDek with tampered encrypted material fails the AEAD tag check`() =
        runTest {
            val generated = service.generateDek()
            val tamperedBytes = java.util.Base64.getDecoder().decode(generated.wrapped.encryptedDekB64)
            // Flip a byte deep enough to not be the IV; AES-GCM should reject this on tag verification.
            tamperedBytes[tamperedBytes.size - 1] = (tamperedBytes[tamperedBytes.size - 1].toInt() xor 0x01).toByte()
            val tampered =
                WrappedDek(
                    kemCiphertextB64 = generated.wrapped.kemCiphertextB64,
                    encryptedDekB64 = java.util.Base64.getEncoder().encodeToString(tamperedBytes),
                )

            assertThrows(javax.crypto.AEADBadTagException::class.java) {
                kotlinx.coroutines.runBlocking { service.unwrapDek(tampered) }
            }
        }

    @Test
    fun `HKDF derivation is deterministic for the same shared secret`() {
        val sharedSecret = ByteArray(32) { (it + 7).toByte() }

        val (aesKey1, adSubkey1) = MlKemService.deriveKeys(sharedSecret)
        val (aesKey2, adSubkey2) = MlKemService.deriveKeys(sharedSecret)

        assertTrue(aesKey1.contentEquals(aesKey2))
        assertTrue(adSubkey1.contentEquals(adSubkey2))
        // Domain-separation: AES key and AD-subkey are independent halves of the same OKM.
        assertFalse(aesKey1.contentEquals(adSubkey1))
        assertEquals(MlKemService.DEK_BYTES, aesKey1.size)
        assertEquals(MlKemService.DEK_BYTES, adSubkey1.size)
    }

    @Test
    fun `HKDF derivation differs across distinct shared secrets`() {
        val secretA = ByteArray(32) { 1 }
        val secretB = ByteArray(32) { 2 }

        val (aesKeyA, _) = MlKemService.deriveKeys(secretA)
        val (aesKeyB, _) = MlKemService.deriveKeys(secretB)

        assertFalse(aesKeyA.contentEquals(aesKeyB))
    }

    @Test
    fun `getPublicKeyFingerprint returns a non-blank SHA-256 colon-hex string`() {
        val fp = service.getPublicKeyFingerprint()
        assertTrue(fp.isNotBlank())
        // 32 bytes × 2 hex chars + 31 colons = 95 characters
        assertEquals(95, fp.length)
        assertTrue(fp.all { it.isDigit() || it in 'a'..'f' || it == ':' })
    }

    @Test
    fun `fromEnv returns null when ML_KEM env vars are absent`() {
        // The test environment does not have ML_KEM_PUBLIC_KEY / ML_KEM_PRIVATE_KEY set.
        assertNull(MlKemCryptoKeyService.fromEnv())
    }

    @Test
    fun `generateNewKekPair returns base64 keys of the expected ML-KEM-768 sizes`() {
        val pair = service.generateNewKekPair()

        val pubBytes = java.util.Base64.getDecoder().decode(pair.publicKeyB64)
        val privBytes = java.util.Base64.getDecoder().decode(pair.privateKeyB64)

        assertEquals(MlKemService.PUBLIC_KEY_BYTES, pubBytes.size)
        assertEquals(MlKemService.PRIVATE_KEY_BYTES, privBytes.size)
        assertTrue(service.isAvailable)
    }
}
