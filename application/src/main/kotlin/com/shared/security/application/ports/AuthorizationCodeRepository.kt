package com.shared.security.application.ports

import com.shared.security.domain.oauth.AuthorizationCode

/**
 * Persistence port for single-use OAuth authorization codes (proposal §4.2; RFC 6749 §4.1).
 *
 * Codes are stored hashed (one-way) — the port deals only in [AuthorizationCode] VOs whose
 * `codeHash` is already the hash of the high-entropy value, never the plaintext code.
 *
 * **Scope note:** the table + this port land with the provider skeleton so the schema exists;
 * the issue path (`/authorize`) and the redeem path (`/token` authorization-code grant) that
 * exercise [insert]/[markRedeemed] arrive in later phases.
 */
interface AuthorizationCodeRepository {
    /** Persist a freshly-issued code. */
    suspend fun insert(code: AuthorizationCode): Unit

    /** Look up a code by its one-way hash, or null if unknown. */
    suspend fun findByHash(codeHash: ByteArray): AuthorizationCode?

    /**
     * Atomically mark the code as redeemed. Returns true on success; returns false when the
     * code was already redeemed (the single-use guard — a false here is grounds to treat the
     * redemption as a replay per RFC 6749 §4.1.2).
     */
    suspend fun markRedeemed(codeHash: ByteArray): Boolean
}
