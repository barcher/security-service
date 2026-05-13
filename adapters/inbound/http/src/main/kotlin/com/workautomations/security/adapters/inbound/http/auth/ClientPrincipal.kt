package com.workautomations.security.adapters.inbound.http.auth

import io.ktor.server.application.ApplicationCall
import io.ktor.util.AttributeKey

/**
 * Identity of an authenticated mTLS client, extracted from the verified client certificate
 * chain by [MtlsAuthPlugin].
 *
 * Routes read this via `call.clientPrincipal()` to know who is calling. The subject DN is
 * also used as the rate-limit bucket key (SKS-B05) and as the `actor_subject` column on
 * every audit event the call produces.
 */
data class ClientPrincipal(
    /** Fully-qualified X.509 subject DN, e.g. `CN=monolith-app,O=WorkAutomations,L=Local`. */
    val subjectDn: String,
    /** SHA-256 fingerprint of the leaf cert (colon-hex). Useful in audit detail. */
    val certFingerprint: String,
)

internal val ClientPrincipalKey: AttributeKey<ClientPrincipal> = AttributeKey("security.client-principal")

/** Returns the authenticated principal, or null when the call has not passed mTLS auth. */
fun ApplicationCall.clientPrincipal(): ClientPrincipal? =
    if (attributes.contains(ClientPrincipalKey)) attributes[ClientPrincipalKey] else null
