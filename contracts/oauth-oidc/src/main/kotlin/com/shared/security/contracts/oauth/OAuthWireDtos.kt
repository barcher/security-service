package com.shared.security.contracts.oauth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * RFC 6749 §5.2 error response body, returned (with the appropriate HTTP status) when a
 * token/authorization request is rejected. The [error] field carries an
 * [OAuthErrorCode.wireValue]; [errorDescription] is human-readable diagnostic text that
 * MUST NOT contain secret material (it can surface in logs and client UIs).
 *
 * Defined up-front so every later grant handler shares one wire shape; no route emits it yet.
 */
@Serializable
data class OAuthErrorResponse(
    val error: String,
    @SerialName("error_description")
    val errorDescription: String? = null,
)

/**
 * RFC 6749 §5.1 successful token response body. `client_credentials` will be the first grant
 * to populate it. Refresh-token and id_token fields are present in the contract for the later
 * phases (the OP owns refresh tokens per the proposal §4.6) but stay null until those grants land.
 */
@Serializable
data class OAuthTokenResponse(
    @SerialName("access_token")
    val accessToken: String,
    @SerialName("token_type")
    val tokenType: String = "Bearer",
    @SerialName("expires_in")
    val expiresIn: Long,
    val scope: String? = null,
    @SerialName("id_token")
    val idToken: String? = null,
    @SerialName("refresh_token")
    val refreshToken: String? = null,
)
