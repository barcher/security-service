package com.shared.security.contracts.oauth

/**
 * OAuth 2.0 / OIDC protocol error codes.
 *
 * The values follow the RFC-registered wire spellings exactly (RFC 6749 §5.2 for the
 * token-endpoint errors, RFC 6749 §4.1.2.1 for the authorization-endpoint errors). These
 * are the `error` field of an [OAuthErrorResponse] body and MUST NOT be renamed — relying
 * parties match on the registered string.
 *
 * The provider skeleton serves only OIDC discovery today, so no grant actually emits one of
 * these yet. The full set is defined up-front so the `client_credentials` grant and the
 * authorization-code flow (added later) bind to a single source of truth rather than
 * scattering string literals across route handlers.
 */
enum class OAuthErrorCode(val wireValue: String) {
    /** The request is missing a required parameter or is otherwise malformed. */
    INVALID_REQUEST("invalid_request"),

    /** Client authentication failed (unknown client, no/invalid client auth). */
    INVALID_CLIENT("invalid_client"),

    /** The provided authorization grant or refresh token is invalid/expired/revoked. */
    INVALID_GRANT("invalid_grant"),

    /** The authenticated client is not authorized to use this grant type. */
    UNAUTHORIZED_CLIENT("unauthorized_client"),

    /** The grant type is not supported by the authorization server. */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),

    /** The requested scope is invalid, unknown, malformed, or exceeds what is granted. */
    INVALID_SCOPE("invalid_scope"),

    /** The resource owner or authorization server denied the request. */
    ACCESS_DENIED("access_denied"),

    /** The authorization server does not support obtaining a token via this method. */
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),

    /** The authorization server encountered an unexpected condition. */
    SERVER_ERROR("server_error"),

    /** The authorization server is temporarily unable to handle the request. */
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
    ;

    companion object {
        /** Resolve a registered wire spelling back to its enum, or null if unrecognized. */
        fun fromWireValue(value: String): OAuthErrorCode? = entries.firstOrNull { it.wireValue == value }
    }
}
