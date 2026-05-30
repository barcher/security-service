package com.shared.security.domain.oauth

import kotlinx.datetime.Instant

/**
 * A single-use OAuth 2.0 authorization code (RFC 6749 §4.1 + PKCE RFC 7636), issued at
 * `/authorize` and redeemed once at `/token`.
 *
 * **Stored hashed, never plaintext** ([codeHash]). Like the refresh token, an authorization
 * code is a bearer credential the provider verifies by re-hashing the presented value — it
 * is therefore a one-way hash with no `*_dek_handle` envelope (proposal §6.1 / §4.6 same
 * rationale). The PKCE [codeChallenge] binds the code to the client's verifier so an
 * intercepted code cannot be redeemed without the original verifier.
 *
 * The provider skeleton defines the VO + its backing table/migration; the `/authorize` issue
 * path and the `/token` redeem path land in later phases.
 *
 * @property codeHash one-way hash of the high-entropy code value.
 * @property clientId the public/confidential client the code was issued to.
 * @property subject the authenticated end-user (monolith UserId) the code represents.
 * @property redirectUri the exact redirect URI the code is bound to (RFC 6749 §4.1.3).
 * @property codeChallenge PKCE code challenge (RFC 7636); [codeChallengeMethod] is always S256.
 * @property scopes the scopes consented at `/authorize`.
 * @property issuedAt issuance time.
 * @property expiresAt short-lived expiry; an expired code is invalid even if unredeemed.
 * @property redeemedAt set when the code is consumed; a second redemption attempt is rejected
 *   (and, per RFC 6749 §4.1.2, is grounds to revoke tokens already issued for the code).
 */
data class AuthorizationCode(
    val codeHash: ByteArray,
    val clientId: String,
    val subject: String,
    val redirectUri: String,
    val codeChallenge: String,
    val codeChallengeMethod: PkceChallengeMethod,
    val scopes: Set<OAuthScope>,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val redeemedAt: Instant? = null,
) {
    fun isExpiredAt(now: Instant): Boolean = now >= expiresAt

    fun isRedeemed(): Boolean = redeemedAt != null

    // Identity equality: AuthorizationCode rows are unique by codeHash, but the data class
    // carries a ByteArray, so the generated structural equals/hashCode would be wrong
    // (array identity). Compare on the hash content explicitly.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AuthorizationCode) return false
        return codeHash.contentEquals(other.codeHash)
    }

    override fun hashCode(): Int = codeHash.contentHashCode()
}

/** PKCE code-challenge method. Only S256 is supported (proposal §4.2: no `plain`). */
enum class PkceChallengeMethod(val wireValue: String) {
    S256("S256"),
}
