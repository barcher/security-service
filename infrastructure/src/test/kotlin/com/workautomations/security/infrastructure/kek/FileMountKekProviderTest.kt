package com.workautomations.security.infrastructure.kek

import com.workautomations.security.application.ports.KekUnavailableException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class FileMountKekProviderTest {
    private lateinit var tempDir: Path

    @BeforeEach
    fun setUp() {
        tempDir = Files.createTempDirectory("kek-mount-test")
    }

    @AfterEach
    fun tearDown() {
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `loads public and private key when both files present`() {
        Files.writeString(tempDir.resolve(FileMountKekProvider.PUBLIC_KEY_FILE), "PUBLIC_B64_VALUE")
        Files.writeString(tempDir.resolve(FileMountKekProvider.PRIVATE_KEY_FILE), "PRIVATE_B64_VALUE")

        val material = FileMountKekProvider(tempDir).loadKekMaterial()

        assertEquals("PUBLIC_B64_VALUE", material.publicKeyB64)
        assertEquals("PRIVATE_B64_VALUE", material.privateKeyB64)
    }

    @Test
    fun `trims surrounding whitespace and newlines from file content`() {
        Files.writeString(tempDir.resolve(FileMountKekProvider.PUBLIC_KEY_FILE), "  PUB  \n")
        Files.writeString(tempDir.resolve(FileMountKekProvider.PRIVATE_KEY_FILE), "\nPRIV\n")

        val material = FileMountKekProvider(tempDir).loadKekMaterial()

        assertEquals("PUB", material.publicKeyB64)
        assertEquals("PRIV", material.privateKeyB64)
    }

    @Test
    fun `fails closed when public key file is missing`() {
        Files.writeString(tempDir.resolve(FileMountKekProvider.PRIVATE_KEY_FILE), "PRIV")

        assertThrows(KekUnavailableException::class.java) {
            FileMountKekProvider(tempDir).loadKekMaterial()
        }
    }

    @Test
    fun `fails closed when private key file is missing`() {
        Files.writeString(tempDir.resolve(FileMountKekProvider.PUBLIC_KEY_FILE), "PUB")

        assertThrows(KekUnavailableException::class.java) {
            FileMountKekProvider(tempDir).loadKekMaterial()
        }
    }

    @Test
    fun `fails closed when public key file is empty`() {
        Files.writeString(tempDir.resolve(FileMountKekProvider.PUBLIC_KEY_FILE), "   \n")
        Files.writeString(tempDir.resolve(FileMountKekProvider.PRIVATE_KEY_FILE), "PRIV")

        assertThrows(KekUnavailableException::class.java) {
            FileMountKekProvider(tempDir).loadKekMaterial()
        }
    }

    @Test
    fun `fails closed when private key file is empty`() {
        Files.writeString(tempDir.resolve(FileMountKekProvider.PUBLIC_KEY_FILE), "PUB")
        Files.writeString(tempDir.resolve(FileMountKekProvider.PRIVATE_KEY_FILE), "")

        assertThrows(KekUnavailableException::class.java) {
            FileMountKekProvider(tempDir).loadKekMaterial()
        }
    }
}
