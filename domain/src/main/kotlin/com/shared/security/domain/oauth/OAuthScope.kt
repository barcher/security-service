package com.shared.security.domain.oauth

/**
 * An OAuth scope, modelled as a value object over its wire token (a space-delimited entry
 * in an OAuth `scope` parameter — RFC 6749 §3.3).
 *
 * Scopes are validated structurally only here (non-blank, no whitespace, ASCII-printable
 * per the RFC 6749 `scope-token` ABNF). Whether a given scope is *grantable to a particular
 * client* is an authorization-policy decision that lives in the application layer against
 * the client registry — not in this VO.
 */
@JvmInline
value class OAuthScope private constructor(val value: String) {
    companion object {
        /** OIDC base scope; presence triggers id_token issuance in later phases. */
        val OPENID = OAuthScope("openid")

        fun of(raw: String): OAuthScope {
            require(raw.isNotBlank()) { "scope must not be blank" }
            require(raw.none { it.isWhitespace() }) { "scope token must not contain whitespace: '$raw'" }
            require(raw.all { it.code in MIN_PRINTABLE..MAX_PRINTABLE }) {
                "scope token must be ASCII-printable: '$raw'"
            }
            return OAuthScope(raw)
        }

        /** Parse a space-delimited OAuth `scope` string into its constituent scopes. */
        fun parseList(raw: String): List<OAuthScope> = raw.split(" ").filter { it.isNotBlank() }.map { of(it) }

        private const val MIN_PRINTABLE = 0x21
        private const val MAX_PRINTABLE = 0x7E
    }
}
