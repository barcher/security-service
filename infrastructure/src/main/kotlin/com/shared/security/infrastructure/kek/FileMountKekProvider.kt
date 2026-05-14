package com.shared.security.infrastructure.kek

import com.shared.security.application.ports.KekProviderPort
import com.shared.security.application.ports.KekUnavailableException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path

/**
 * Reads KEK material from a mounted secret directory.
 *
 * Expected layout (matches k3s / docker-secrets convention):
 * ```
 *   <mountDir>/ml_kem_public_key    # base64-encoded public key, 1580 chars
 *   <mountDir>/ml_kem_private_key   # base64-encoded private key, 3204 chars
 * ```
 *
 * Plaintext base64 in the file is intentional: the secret store (docker-secrets,
 * k8s Secret, Vault) is responsible for confidentiality at rest. The application
 * reads the file once at startup and never writes back.
 *
 * **Why files, not env vars:** post-Phase 14, the monolith MUST NOT hold the KEK,
 * and env vars leak via `/proc/<pid>/environ`, `ps eww`, and any subprocess inheriting
 * the environment. A file mount has a much smaller leak surface and matches the
 * standard k8s/docker-secrets pattern.
 */
class FileMountKekProvider(private val mountDir: Path) : KekProviderPort {
    override fun loadKekMaterial(): KekProviderPort.KekMaterial {
        val pub = readOrFail(mountDir.resolve(PUBLIC_KEY_FILE))
        val priv = readOrFail(mountDir.resolve(PRIVATE_KEY_FILE))
        return KekProviderPort.KekMaterial(publicKeyB64 = pub, privateKeyB64 = priv)
    }

    private fun readOrFail(path: Path): String =
        try {
            val content = Files.readString(path).trim()
            if (content.isEmpty()) {
                throw KekUnavailableException("KEK material file is empty: $path")
            }
            content
        } catch (e: NoSuchFileException) {
            throw KekUnavailableException("KEK material file not found: $path", e)
        } catch (e: java.io.IOException) {
            throw KekUnavailableException("Failed to read KEK material file: $path", e)
        }

    companion object {
        const val PUBLIC_KEY_FILE = "ml_kem_public_key"
        const val PRIVATE_KEY_FILE = "ml_kem_private_key"

        /** Read mount directory from env. Defaults to `/run/secrets/kek` (docker-secrets convention). */
        fun fromEnv(): FileMountKekProvider {
            val dir = System.getenv("KEK_MOUNT_DIR") ?: DEFAULT_MOUNT_DIR
            return FileMountKekProvider(Path.of(dir))
        }

        private const val DEFAULT_MOUNT_DIR = "/run/secrets/kek"
    }
}
