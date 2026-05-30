package com.shared.security.adapters.inbound.oauth

import com.shared.security.application.usecases.oauth.BuildOidcDiscoveryUseCase
import com.shared.security.application.usecases.oauth.OidcDiscoveryMetadata
import com.shared.security.application.usecases.oauth.OidcProviderConfig
import com.shared.security.contracts.oauth.OidcDiscoveryDocument
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get

/**
 * `GET /.well-known/openid-configuration` — OpenID Connect Discovery 1.0 metadata.
 *
 * **Metadata only.** This route reads no key material and calls no crypto primitive; it
 * publishes the provider's endpoint + supported-feature metadata. The `jwks_uri` points at
 * the existing `GET /v1/jwks` (proposal R-10) — there is exactly one JWKS document.
 *
 * **Public route.** Discovery is intentionally unauthenticated (it advertises only public
 * metadata), like `/v1/jwks`. The composition root adds [OidcProviderConfig.DISCOVERY_PATH]
 * to the mTLS public-path allow-list so it is reachable without a client certificate.
 *
 * The handler maps the application-layer [OidcDiscoveryMetadata] onto the wire DTO
 * [OidcDiscoveryDocument] from `contracts/oauth-oidc`, keeping serialization out of the
 * application layer.
 */
fun Routing.installOidcDiscoveryRoutes(buildDiscovery: BuildOidcDiscoveryUseCase) {
    get(OidcProviderConfig.DISCOVERY_PATH) {
        val doc = buildDiscovery.build().toWireDocument()
        // Discovery is stable metadata; allow a long cache window (proposal §4.7 surface #2).
        call.response.header(HttpHeaders.CacheControl, "public, max-age=$DISCOVERY_MAX_AGE_SECONDS")
        call.respond(HttpStatusCode.OK, doc)
    }
}

private fun OidcDiscoveryMetadata.toWireDocument(): OidcDiscoveryDocument =
    OidcDiscoveryDocument(
        issuer = issuer,
        authorizationEndpoint = authorizationEndpoint,
        tokenEndpoint = tokenEndpoint,
        userinfoEndpoint = userinfoEndpoint,
        jwksUri = jwksUri,
        scopesSupported = scopesSupported,
        responseTypesSupported = responseTypesSupported,
        grantTypesSupported = grantTypesSupported,
        tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported,
        claimsSupported = claimsSupported,
    )

private const val DISCOVERY_MAX_AGE_SECONDS: Long = 86_400L
