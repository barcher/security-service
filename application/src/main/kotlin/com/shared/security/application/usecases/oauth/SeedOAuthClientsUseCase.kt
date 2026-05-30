package com.shared.security.application.usecases.oauth

import com.shared.security.application.ports.OAuthClientStore
import com.shared.security.domain.oauth.OAuthClient

/**
 * Seeds the static OAuth client registry (proposal §4.9) into `oauth_clients` on startup.
 *
 * The registry is provisioned, not dynamically registered (proposal R-12 / OQ-6): the set of
 * first-party clients is fixed config. This use case inserts each declared client only if its
 * `client_id` is absent, so running it on every boot is idempotent and never overwrites an
 * operator's later edit (the admin CLI in a future phase is the mutation path).
 *
 * The provider skeleton wires the mechanism and verifies it inserts; the clients it seeds get
 * their grant handlers in later phases. The concrete client list is supplied by the
 * composition root so the application layer carries no deployment-specific DNs.
 *
 * @return the number of clients newly inserted (0 when all were already present).
 */
class SeedOAuthClientsUseCase(
    private val store: OAuthClientStore,
    private val clients: List<OAuthClient>,
) {
    suspend fun seed(): Int {
        var inserted = 0
        for (client in clients) {
            if (store.insertIfAbsent(client)) inserted++
        }
        return inserted
    }
}
