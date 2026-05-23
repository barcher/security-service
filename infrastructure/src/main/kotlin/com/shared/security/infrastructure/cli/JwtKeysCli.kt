package com.shared.security.infrastructure.cli

import com.shared.security.adapters.outbound.crypto.KekEnvelopeAdapter
import com.shared.security.adapters.outbound.crypto.MlKemCryptoKeyService
import com.shared.security.adapters.outbound.jwtsigning.Es256JwtSigningKeyAdapter
import com.shared.security.adapters.outbound.persistence.ExposedJwtSigningKeyRepository
import com.shared.security.adapters.outbound.persistence.ExposedKekRepository
import com.shared.security.adapters.outbound.persistence.SecurityDatabase
import com.shared.security.adapters.outbound.persistence.SecurityDatabaseConfig
import com.shared.security.adapters.outbound.persistence.SecurityFlywayMigrator
import com.shared.security.application.usecases.jwt.ActivateJwtSigningKeyUseCase
import com.shared.security.application.usecases.jwt.GenerateJwtSigningKeyPairUseCase
import com.shared.security.infrastructure.audit.Slf4jAuditLogAdapter
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import kotlin.system.exitProcess

/**
 * Operator CLI for JWT signing-key lifecycle. Subcommands:
 *
 * ```
 * jwt-keys generate-pair [--activate] [--operator-email=<email>]
 * jwt-keys activate --kid=<hex> [--operator-email=<email>]
 * ```
 *
 * **`generate-pair`** — mints a fresh ES256 keypair, wraps the private bytes under the
 * current ACTIVE KEK via `KekEnvelopePort`, and inserts a STAGED row in
 * `jwt_signing_keys`. Used during the HSM ceremony (see `HSM_KEY_CEREMONY.md` §3) and
 * during rotation. With `--activate`, immediately promotes the new key to ACTIVE — only
 * appropriate at bootstrap when there is no existing ACTIVE row.
 *
 * **`activate`** — promotes a STAGED row identified by hex `kid` to ACTIVE. The existing
 * ACTIVE row (if any) is demoted to PRIOR in the same transaction; the schema's
 * singleton-ACTIVE generated-column index enforces the invariant.
 *
 * Both subcommands write the corresponding `JWKS_KEY_GENERATED` / `JWKS_KEY_ACTIVATED`
 * audit row through the same `AuditLogPort` used by the running server. The CLI is
 * authenticated only by physical access to the security-service host + DB (same trust
 * model as `generate-kek` / `import-monolith-deks`); see CLAUDE.md for the operator
 * runbook.
 */
class JwtKeysCli {
    private val logger = LoggerFactory.getLogger(JwtKeysCli::class.java)

    fun run(args: List<String>) {
        val subcommand = args.firstOrNull() ?: usageAndExit("missing subcommand")
        val rest = args.drop(1)
        when (subcommand) {
            "generate-pair" -> runGeneratePair(rest)
            "activate" -> runActivate(rest)
            else -> usageAndExit("unknown subcommand '$subcommand'")
        }
    }

    private fun runGeneratePair(args: List<String>) {
        val opts = parseArgs(args)
        val (db, useCase) = wireGenerate()
        try {
            val record = runBlocking { useCase.execute(actorSubject = opts.actor) }
            val kidHex = record.kid.joinToString("") { "%02x".format(it) }
            println("jwt-keys generate-pair: STAGED kid=$kidHex wrappedUnderKekId=${record.wrappedUnderKekId}")
            if (opts.activate) {
                val activate = wireActivate(db)
                val result = runBlocking { activate.execute(record.kid, actorSubject = opts.actor) }
                when (result) {
                    ActivateJwtSigningKeyUseCase.Result.Activated ->
                        println("jwt-keys generate-pair: PROMOTED kid=$kidHex to ACTIVE (was STAGED)")
                    ActivateJwtSigningKeyUseCase.Result.NotStaged ->
                        error("internal: just-inserted STAGED kid=$kidHex was not promotable")
                }
            }
        } finally {
            db.close()
        }
    }

    private fun runActivate(args: List<String>) {
        val opts = parseArgs(args)
        val kidHex =
            opts.kidHex ?: usageAndExit("--kid=<hex> is required for activate")
        val kid =
            runCatching { hexDecode(kidHex) }.getOrElse {
                usageAndExit("--kid must be 32 hex chars (16 bytes)")
            }
        val db = SecurityDatabase.create(SecurityDatabaseConfig.fromEnv())
        try {
            SecurityFlywayMigrator(db.dataSource).migrate()
            val useCase = wireActivate(db)
            val result = runBlocking { useCase.execute(kid, actorSubject = opts.actor) }
            when (result) {
                ActivateJwtSigningKeyUseCase.Result.Activated ->
                    println("jwt-keys activate: kid=$kidHex is now ACTIVE")
                ActivateJwtSigningKeyUseCase.Result.NotStaged -> {
                    System.err.println("jwt-keys activate: kid=$kidHex was not STAGED (already promoted or missing)")
                    exitProcess(EXIT_NOT_STAGED)
                }
            }
        } finally {
            db.close()
        }
    }

    private fun wireGenerate(): Pair<SecurityDatabase, GenerateJwtSigningKeyPairUseCase> {
        val db = SecurityDatabase.create(SecurityDatabaseConfig.fromEnv())
        SecurityFlywayMigrator(db.dataSource).migrate()
        val crypto =
            checkNotNull(MlKemCryptoKeyService.fromEnv()) {
                "ML_KEM_PUBLIC_KEY_CURRENT and friends are not set; cannot wrap a JWT signing key without an ACTIVE KEK"
            }
        val kekRepo = ExposedKekRepository(db.database)
        val kekEnvelope = KekEnvelopeAdapter(crypto, kekRepo)
        val signing = Es256JwtSigningKeyAdapter()
        val jwtRepo = ExposedJwtSigningKeyRepository(db.database)
        val auditLog = Slf4jAuditLogAdapter()
        val useCase = GenerateJwtSigningKeyPairUseCase(signing, kekEnvelope, jwtRepo, auditLog)
        logger.info("jwt-keys: wired generate-pair against KEK envelope adapter + ES256 signing service")
        return db to useCase
    }

    private fun wireActivate(db: SecurityDatabase): ActivateJwtSigningKeyUseCase {
        val jwtRepo = ExposedJwtSigningKeyRepository(db.database)
        val auditLog = Slf4jAuditLogAdapter()
        return ActivateJwtSigningKeyUseCase(jwtRepo, auditLog)
    }

    private data class Opts(
        val activate: Boolean,
        val kidHex: String?,
        val actor: String?,
    )

    private fun parseArgs(args: List<String>): Opts {
        val map =
            args.mapNotNull {
                it.takeIf { a -> a.startsWith("--") }?.substring(2)?.split("=", limit = 2)
            }.associate { it[0] to (it.getOrNull(1) ?: "true") }
        return Opts(
            activate = map["activate"] == "true",
            kidHex = map["kid"],
            actor = map["operator-email"]?.let { "operator:$it" },
        )
    }

    private fun hexDecode(hex: String): ByteArray {
        require(hex.length == HEX_LENGTH) { "kid hex must be $HEX_LENGTH chars" }
        return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(HEX_RADIX).toByte() }
    }

    private fun usageAndExit(message: String): Nothing {
        System.err.println(
            "$message\n\nUsage:\n" +
                "  jwt-keys generate-pair [--activate] [--operator-email=<email>]\n" +
                "  jwt-keys activate --kid=<hex32> [--operator-email=<email>]",
        )
        exitProcess(EXIT_USAGE)
    }

    private companion object {
        private const val EXIT_USAGE = 2
        private const val EXIT_NOT_STAGED = 3
        private const val HEX_LENGTH = 32
        private const val HEX_RADIX = 16
    }
}
