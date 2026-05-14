package com.shared.security.infrastructure.cli

import com.shared.security.adapters.outbound.crypto.MlKemCryptoKeyService
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.adapters.outbound.persistence.tables.DeksTable
import com.shared.security.adapters.outbound.persistence.tables.KekStatus
import com.shared.security.adapters.outbound.persistence.tables.KeksTable
import com.shared.security.application.ports.WrappedDek
import com.shared.security.infrastructure.kek.FileMountKekProvider
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.api.ExposedBlob
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.sql.DriverManager
import kotlin.system.exitProcess

/**
 * One-shot CLI: imports each row from the monolith's `principal_encryption_keys` table
 * into the security-service `deks` table, rewrapping under the active security-service
 * KEK.
 *
 * Usage (inside the `security-app` container):
 *
 * ```
 * docker compose exec security-app /app/bin/infrastructure import-monolith-deks \
 *     --source-jdbc-url=jdbc:mysql://mysql:3306/workautomations \
 *     --source-user=root \
 *     --source-password=rootpassword
 * ```
 *
 * **Preconditions:**
 *
 * 1. `SECURITY_DB_ENABLED=true` and the security-service Flyway migrations have applied.
 * 2. There is at least one `keks` row with `status='ACTIVE'`. The CLI does NOT create one
 *    — operators must seed the row before running the import (the row references KEK
 *    material on disk that the operator already mounted).
 * 3. The KEK material currently mounted on the security-service is the same KEK that
 *    wrapped the monolith's legacy DEKs — i.e. the operator promoted the legacy
 *    `ML_KEM_PUBLIC_KEY` / `ML_KEM_PRIVATE_KEY` env vars to the file-mount secret store.
 *    If the legacy KEK is different, the CLI fails on the first unwrap with
 *    `AEADBadTagException` and the operator must either supply the legacy KEK as
 *    additional args (follow-on) or rotate everything via the legacy path first.
 *
 * **Idempotency:** the `deks.legacy_key_id` column has a UNIQUE index (V4). Re-running
 * the CLI is a no-op for rows already imported; only newly-added legacy keys are
 * processed on a re-run.
 */
class ImportMonolithDeksCli {
    private val logger = LoggerFactory.getLogger(ImportMonolithDeksCli::class.java)
    private val random = SecureRandom()

    @Suppress("NestedBlockDepth") // JDBC + Exposed nest deeply by their nature; refactoring obscures the loop
    fun run(args: List<String>) {
        val opts = parseArgs(args)
        logger.info("import-monolith-deks: reading from {} (user={})", opts.sourceJdbcUrl, opts.sourceUser)

        val targetDbConfig = SecurityDatabaseConfig.fromEnv()
        val securityDb = SecurityDatabase.create(targetDbConfig)
        SecurityFlywayMigrator(securityDb.dataSource).migrate()

        val crypto =
            checkNotNull(MlKemCryptoKeyService.fromEnv()) {
                "ML_KEM_PUBLIC_KEY / ML_KEM_PRIVATE_KEY env vars not set; mount the KEK material first"
            }
        // Avoid an "unused" warning during dev — also verifies the KEK provider env path works.
        FileMountKekProvider.fromEnv()

        val activeKekId =
            transaction(securityDb.database) {
                KeksTable
                    .selectAll()
                    .where { KeksTable.status eq KekStatus.ACTIVE }
                    .limit(1)
                    .firstOrNull()
                    ?.get(KeksTable.id)
            } ?: error(
                "No ACTIVE row in security_keys.keks — seed the row before running import-monolith-deks",
            )

        var imported = 0
        var skipped = 0
        DriverManager.getConnection(opts.sourceJdbcUrl, opts.sourceUser, opts.sourcePassword).use { conn ->
            conn.prepareStatement(SELECT_LEGACY_KEYS).use { ps ->
                ps.executeQuery().use { rs ->
                    while (rs.next()) {
                        val legacyId = rs.getString("id")
                        if (alreadyImported(securityDb, legacyId)) {
                            skipped++
                            continue
                        }
                        val kemCt = rs.getString("kem_ciphertext")
                        val encDek = rs.getString("encrypted_dek")
                        importOne(crypto, securityDb, activeKekId, legacyId, kemCt, encDek)
                        imported++
                    }
                }
            }
        }
        logger.info("import-monolith-deks complete: imported={} skipped={}", imported, skipped)
        securityDb.close()
    }

    private fun alreadyImported(
        db: SecurityDatabase,
        legacyId: String,
    ): Boolean =
        transaction(db.database) {
            DeksTable.selectAll().where { DeksTable.legacyKeyId eq legacyId }.limit(1).firstOrNull() != null
        }

    private fun importOne(
        crypto: MlKemCryptoKeyService,
        db: SecurityDatabase,
        activeKekId: String,
        legacyId: String,
        kemCiphertextB64: String,
        encryptedDekB64: String,
    ) {
        val plaintext =
            runBlocking {
                crypto.unwrapDek(WrappedDek(kemCiphertextB64 = kemCiphertextB64, encryptedDekB64 = encryptedDekB64))
            }
        try {
            val rewrapped = runBlocking { crypto.wrapDek(plaintext) }
            val handle = ByteArray(HANDLE_BYTES).also(random::nextBytes)
            val now = Clock.System.now()
            transaction(db.database) {
                DeksTable.insert {
                    it[DeksTable.handle] = handle
                    it[kekId] = activeKekId
                    it[wrappedDekBytes] = ExposedBlob(rewrapped.encryptedDekB64.toByteArray(Charsets.US_ASCII))
                    it[createdAt] = now
                    it[updatedAt] = now
                    it[legacyKeyId] = legacyId
                }
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private data class Opts(
        val sourceJdbcUrl: String,
        val sourceUser: String,
        val sourcePassword: String,
    )

    private fun parseArgs(args: List<String>): Opts {
        val map =
            args.mapNotNull { it.takeIf { it.startsWith("--") }?.substring(2)?.split("=", limit = 2) }
                .associate { it[0] to (it.getOrNull(1) ?: "") }
        val url = map["source-jdbc-url"] ?: usageAndExit("--source-jdbc-url is required")
        val user = map["source-user"] ?: usageAndExit("--source-user is required")
        val password = map["source-password"] ?: usageAndExit("--source-password is required")
        return Opts(sourceJdbcUrl = url, sourceUser = user, sourcePassword = password)
    }

    private fun usageAndExit(message: String): Nothing {
        System.err.println(
            "$message\n\nUsage: import-monolith-deks " +
                "--source-jdbc-url=<url> --source-user=<u> --source-password=<p>",
        )
        exitProcess(USAGE_EXIT)
    }

    companion object {
        private const val HANDLE_BYTES = 16
        private const val USAGE_EXIT = 2
        private const val SELECT_LEGACY_KEYS =
            "SELECT id, kem_ciphertext, encrypted_dek FROM principal_encryption_keys"
    }
}
