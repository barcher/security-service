package com.shared.security.domain.oauth

/**
 * OAuth 2.0 grant types in scope for the provider's v1 (proposal §4.2).
 *
 * Only [CLIENT_CREDENTIALS], [AUTHORIZATION_CODE] and [REFRESH_TOKEN] are in scope; implicit,
 * ROPC/password, and device-code grants are deliberately excluded (proposal §4.2). The
 * [wireValue] is the RFC-registered `grant_type` request-parameter spelling and is the value
 * advertised in the OIDC discovery document's `grant_types_supported` list.
 *
 * The provider skeleton defines the type; the handlers that mint tokens for each grant land
 * in later phases.
 */
enum class OAuthGrantType(val wireValue: String) {
    CLIENT_CREDENTIALS("client_credentials"),
    AUTHORIZATION_CODE("authorization_code"),
    REFRESH_TOKEN("refresh_token"),
    ;

    companion object {
        fun fromWireValue(value: String): OAuthGrantType? = entries.firstOrNull { it.wireValue == value }
    }
}
