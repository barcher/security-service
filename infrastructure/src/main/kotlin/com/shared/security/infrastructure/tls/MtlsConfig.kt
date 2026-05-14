package com.shared.security.infrastructure.tls

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore

/**
 * mTLS configuration loaded from environment variables.
 *
 * The security service speaks TLS 1.3 only and requires every inbound connection to present
 * a valid client certificate issued by [trustStorePath]'s CA. Server identity comes from
 * [keyStorePath] (a PKCS12 file holding the server's ECDSA P-384 cert + key under
 * [keyStoreAlias]).
 *
 * **Why PKCS12 over JKS:** PKCS12 is the IETF-standard format (RFC 7292) and the JDK
 * default since 9; JKS is deprecated. PKCS12 files are produced by `openssl pkcs12 -export`.
 */
data class MtlsConfig(
    val keyStorePath: Path,
    val keyStorePassword: CharArray,
    val keyStoreAlias: String,
    val trustStorePath: Path,
    val trustStorePassword: CharArray,
) {
    /** Load and return the server keystore (PKCS12). Throws [MtlsConfigException] on failure. */
    fun loadKeyStore(): KeyStore = loadStore(keyStorePath, keyStorePassword, "key")

    /** Load and return the truststore (PKCS12). Throws [MtlsConfigException] on failure. */
    fun loadTrustStore(): KeyStore = loadStore(trustStorePath, trustStorePassword, "trust")

    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)

    companion object {
        private const val STORE_TYPE = "PKCS12"

        /**
         * Load [MtlsConfig] from env vars:
         *
         * - `SECURITY_SERVICE_KEYSTORE_PATH`     (required)
         * - `SECURITY_SERVICE_KEYSTORE_PASSWORD` (required)
         * - `SECURITY_SERVICE_KEYSTORE_ALIAS`    (default: `security-service`)
         * - `SECURITY_SERVICE_TRUSTSTORE_PATH`   (required)
         * - `SECURITY_SERVICE_TRUSTSTORE_PASSWORD` (required)
         *
         * Returns null when any required var is absent; callers should fall back to plaintext
         * mode (Stream A) in that case while logging a clear warning. mTLS is non-optional
         * in prod — see Phase 14 §3.3.
         */
        fun fromEnv(): MtlsConfig? {
            val ksPath = System.getenv("SECURITY_SERVICE_KEYSTORE_PATH") ?: return null
            val ksPwd = System.getenv("SECURITY_SERVICE_KEYSTORE_PASSWORD") ?: return null
            val ksAlias = System.getenv("SECURITY_SERVICE_KEYSTORE_ALIAS") ?: "security-service"
            val tsPath = System.getenv("SECURITY_SERVICE_TRUSTSTORE_PATH") ?: return null
            val tsPwd = System.getenv("SECURITY_SERVICE_TRUSTSTORE_PASSWORD") ?: return null
            return MtlsConfig(
                keyStorePath = Path.of(ksPath),
                keyStorePassword = ksPwd.toCharArray(),
                keyStoreAlias = ksAlias,
                trustStorePath = Path.of(tsPath),
                trustStorePassword = tsPwd.toCharArray(),
            )
        }

        @Suppress("ThrowsCount") // each branch maps a distinct failure mode to MtlsConfigException
        private fun loadStore(
            path: Path,
            password: CharArray,
            label: String,
        ): KeyStore {
            if (!Files.exists(path)) {
                throw MtlsConfigException("$label store file not found: $path")
            }
            return try {
                val ks = KeyStore.getInstance(STORE_TYPE)
                Files.newInputStream(path).use { ks.load(it, password) }
                ks
            } catch (e: IOException) {
                throw MtlsConfigException("Failed to read $label store at $path", e)
            } catch (e: java.security.GeneralSecurityException) {
                throw MtlsConfigException("Failed to load $label store at $path (bad password?)", e)
            }
        }
    }
}

class MtlsConfigException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
