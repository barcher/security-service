package com.shared.security.adapters.outbound.persistence

import com.shared.security.adapters.outbound.persistence.tables.AuthorizationCodesTable
import com.shared.security.application.ports.AuthorizationCodeRepository
import com.shared.security.domain.oauth.AuthorizationCode
import com.shared.security.domain.oauth.OAuthScope
import com.shared.security.domain.oauth.PkceChallengeMethod
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update

/**
 * Exposed-backed store for single-use authorization codes. Codes are looked up + persisted by
 * their one-way `code_hash`; plaintext code values never reach this adapter.
 *
 * The provider skeleton lands the adapter so the schema + port are exercised; the `/authorize`
 * issue path and `/token` redeem path that call these methods arrive in later phases.
 */
class ExposedAuthorizationCodeRepository(
    private val database: Database,
) : AuthorizationCodeRepository {
    override suspend fun insert(code: AuthorizationCode): Unit =
        withContext(Dispatchers.IO) {
            transaction(database) {
                AuthorizationCodesTable.insert {
                    it[codeHash] = code.codeHash
                    it[clientId] = code.clientId
                    it[subject] = code.subject
                    it[redirectUri] = code.redirectUri
                    it[codeChallenge] = code.codeChallenge
                    it[codeChallengeMethod] = code.codeChallengeMethod.wireValue
                    it[scopes] = code.scopes.joinToString(" ") { s -> s.value }
                    it[issuedAt] = code.issuedAt
                    it[expiresAt] = code.expiresAt
                    it[redeemedAt] = code.redeemedAt
                }
                Unit
            }
        }

    override suspend fun findByHash(codeHash: ByteArray): AuthorizationCode? =
        withContext(Dispatchers.IO) {
            transaction(database) {
                AuthorizationCodesTable
                    .selectAll()
                    .where { AuthorizationCodesTable.codeHash eq codeHash }
                    .limit(1)
                    .firstOrNull()
                    ?.toCode()
            }
        }

    override suspend fun markRedeemed(codeHash: ByteArray): Boolean =
        withContext(Dispatchers.IO) {
            transaction(database) {
                // Atomic single-use guard: only flip rows still unredeemed. A second redemption
                // updates zero rows and returns false (a replay signal per RFC 6749 §4.1.2).
                val now = kotlinx.datetime.Clock.System.now()
                val updated =
                    AuthorizationCodesTable.update(
                        {
                            (AuthorizationCodesTable.codeHash eq codeHash) and
                                (AuthorizationCodesTable.redeemedAt.isNull())
                        },
                    ) {
                        it[redeemedAt] = now
                    }
                updated > 0
            }
        }

    private fun ResultRow.toCode(): AuthorizationCode {
        val method =
            PkceChallengeMethod.entries.firstOrNull {
                it.wireValue == this@toCode[AuthorizationCodesTable.codeChallengeMethod]
            } ?: error("Unknown code_challenge_method '${this[AuthorizationCodesTable.codeChallengeMethod]}'")
        return AuthorizationCode(
            codeHash = this[AuthorizationCodesTable.codeHash],
            clientId = this[AuthorizationCodesTable.clientId],
            subject = this[AuthorizationCodesTable.subject],
            redirectUri = this[AuthorizationCodesTable.redirectUri],
            codeChallenge = this[AuthorizationCodesTable.codeChallenge],
            codeChallengeMethod = method,
            scopes =
                this[AuthorizationCodesTable.scopes]
                    .split(" ")
                    .filter { it.isNotBlank() }
                    .map { OAuthScope.of(it) }
                    .toSet(),
            issuedAt = this[AuthorizationCodesTable.issuedAt],
            expiresAt = this[AuthorizationCodesTable.expiresAt],
            redeemedAt = this[AuthorizationCodesTable.redeemedAt],
        )
    }
}
