package com.shared.security.application.ports

import com.shared.security.domain.oauth.OAuthClient

/**
 * Read port over the statically-provisioned OAuth client registry (proposal §4.9).
 *
 * There is no dynamic registration: the registry is seeded into `oauth_clients` and mutated
 * only by an admin CLI in a later phase. This port is the authorization-decision lookup the
 * `client_credentials` grant and the authorization-code flow will use; in the provider
 * skeleton it exists, is wired, and is exercised by the seed mechanism, but no grant handler
 * consumes it yet.
 *
 * Implementations may cache for process lifetime (the registry is static — proposal §4.7
 * cache surface #4); a registry edit busts the cache via an explicit operator action.
 */
interface OAuthClientRegistry {
    /** Resolve a client by its `client_id`, or null if no such client exists. */
    suspend fun findByClientId(clientId: String): OAuthClient?

    /**
     * Resolve a confidential client by its mTLS subject DN (the Gate-1 identity at `/token`).
     * Returns null when no `tls_client_auth` client is bound to [subjectDn].
     */
    suspend fun findBySubjectDn(subjectDn: String): OAuthClient?

    /** Every provisioned client (enabled and disabled). Used by the admin list CLI + seeding. */
    suspend fun findAll(): List<OAuthClient>
}

/**
 * Write port for provisioning the static client registry.
 *
 * Split from [OAuthClientRegistry] (read) so route/use-case code that only needs lookups
 * cannot reach the mutation surface. The boot-time seed mechanism and the later admin CLI are
 * the only writers.
 */
interface OAuthClientStore {
    /**
     * Insert [client] if no client with its `client_id` exists yet. Idempotent: returns false
     * (without modifying the existing row) when the `client_id` is already present, so a
     * repeated seed-on-boot is safe.
     */
    suspend fun insertIfAbsent(client: OAuthClient): Boolean
}
