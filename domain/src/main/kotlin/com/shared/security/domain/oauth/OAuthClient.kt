package com.shared.security.domain.oauth

/**
 * How a client authenticates to the token endpoint (proposal §4.2 / §4.9).
 *
 * - [TLS_CLIENT_AUTH] — confidential clients authenticate by their operational-lane mTLS
 *   client certificate (RFC 8705). The `client_id` is bound 1:1 to the certificate subject
 *   DN; there is no stored shared secret to leak.
 * - [NONE] — public clients (the browser SPA) use PKCE and present no secret.
 *
 * No `client_secret_basic`/`client_secret_post` method exists: the provider deliberately
 * never stores a recoverable client secret (proposal §5).
 */
enum class OAuthClientAuthMethod(val wireValue: String) {
    TLS_CLIENT_AUTH("tls_client_auth"),
    NONE("none"),
    ;

    companion object {
        fun fromWireValue(value: String): OAuthClientAuthMethod? = entries.firstOrNull { it.wireValue == value }
    }
}

/**
 * A statically-provisioned OAuth client (proposal §4.9). There is **no** dynamic client
 * registration in v1; the registry is a fixed, operator-managed set seeded into the
 * `oauth_clients` table.
 *
 * @property clientId stable client identifier (e.g. `workautomations-financial`).
 * @property authMethod how the client proves its identity at `/token`.
 * @property subjectDn for [OAuthClientAuthMethod.TLS_CLIENT_AUTH] clients, the operational-lane
 *   certificate subject DN bound 1:1 to this client. Null for public ([OAuthClientAuthMethod.NONE])
 *   clients. The DN gate composes with — never bypasses — the existing four-lane DN model
 *   (proposal R-4).
 * @property allowedGrantTypes the grants this client may request.
 * @property allowedScopes the scopes this client may be granted.
 * @property allowedAudiences a *superset view* over the existing `SECURITY_JWT_AUDIENCE_ALLOWLIST`
 *   (proposal §4.3); the env allow-list remains the authoritative Gate-2 source.
 * @property enabled a disabled client is rejected at `/token` without being deleted.
 */
data class OAuthClient(
    val clientId: String,
    val authMethod: OAuthClientAuthMethod,
    val subjectDn: String?,
    val allowedGrantTypes: Set<OAuthGrantType>,
    val allowedScopes: Set<OAuthScope>,
    val allowedAudiences: Set<String>,
    val enabled: Boolean,
) {
    init {
        require(clientId.isNotBlank()) { "clientId must not be blank" }
        when (authMethod) {
            OAuthClientAuthMethod.TLS_CLIENT_AUTH ->
                require(!subjectDn.isNullOrBlank()) {
                    "tls_client_auth client '$clientId' must carry a subject DN"
                }
            OAuthClientAuthMethod.NONE ->
                require(subjectDn == null) {
                    "public client '$clientId' must not carry a subject DN"
                }
        }
    }

    fun allows(grantType: OAuthGrantType): Boolean = enabled && grantType in allowedGrantTypes
}
