package com.shared.security.infrastructure.oauth

import com.shared.security.domain.oauth.OAuthClient
import com.shared.security.domain.oauth.OAuthClientAuthMethod
import com.shared.security.domain.oauth.OAuthGrantType
import com.shared.security.domain.oauth.OAuthScope

/**
 * The fixed set of first-party OAuth clients seeded into `oauth_clients` on boot
 * (proposal §4.9). There is no dynamic registration; this list is the registry.
 *
 * It lives in `infrastructure/` (the composition root) — not in the application layer —
 * because the confidential-client subject DNs are deployment identities (the operational-lane
 * certificate DNs from the four-lane model). The application's [com.shared.security.application.usecases.oauth.SeedOAuthClientsUseCase]
 * stays DN-agnostic and just inserts whatever clients it is handed.
 *
 * The operational-lane DNs match CLAUDE.md's four-lane model
 * (`CN=workautomations-{monolith,financial-monolith},O=WorkAutomations`). The browser client
 * is public (PKCE, no secret, no DN). The scope/audience grants are deliberately minimal in
 * the provider skeleton — the grant handlers that consume them land in later phases.
 */
object OAuthClientSeed {
    fun firstPartyClients(): List<OAuthClient> =
        listOf(
            OAuthClient(
                clientId = "workautomations-monolith",
                authMethod = OAuthClientAuthMethod.TLS_CLIENT_AUTH,
                subjectDn = "CN=workautomations-monolith,O=WorkAutomations",
                allowedGrantTypes = setOf(OAuthGrantType.CLIENT_CREDENTIALS),
                allowedScopes = setOf(OAuthScope.of("crypto.dek"), OAuthScope.of("jwt.sign")),
                allowedAudiences = setOf("workautomations-api"),
                enabled = true,
            ),
            OAuthClient(
                clientId = "workautomations-financial",
                authMethod = OAuthClientAuthMethod.TLS_CLIENT_AUTH,
                subjectDn = "CN=workautomations-financial-monolith,O=WorkAutomations",
                allowedGrantTypes = setOf(OAuthGrantType.CLIENT_CREDENTIALS),
                allowedScopes = setOf(OAuthScope.of("crypto.dek")),
                allowedAudiences = setOf("workautomations-api"),
                enabled = true,
            ),
            OAuthClient(
                clientId = "workautomations-frontend",
                authMethod = OAuthClientAuthMethod.NONE,
                subjectDn = null,
                allowedGrantTypes = setOf(OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN),
                allowedScopes = setOf(OAuthScope.OPENID, OAuthScope.of("profile"), OAuthScope.of("email")),
                allowedAudiences = setOf("workautomations-api"),
                enabled = true,
            ),
        )
}
