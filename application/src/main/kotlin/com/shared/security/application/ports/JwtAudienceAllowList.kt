package com.shared.security.application.ports

/**
 * Gate 2 of the two-gate caller-authentication model (Stream K proposal §3.4a). Given
 * a mTLS-verified subject DN and a requested JWT audience, decides whether the calling
 * service is allowed to mint tokens with that audience.
 *
 * Gate 1 (mTLS) is enforced by the existing [com.shared.security.adapters.inbound.http.auth.MtlsAuthPlugin];
 * by the time this port is consulted the subject DN is already verified. Gate 2's
 * purpose is to ensure a leaked operational mTLS cert can mint only the audiences its
 * owning service is allow-listed for, not arbitrary audiences (e.g. a compromised
 * monolith cert cannot mint `workautomations-financial-api` tokens).
 *
 * The default adapter [EnvJwtAudienceAllowList] (lives in `infrastructure/`) reads
 * env vars of the form `SECURITY_JWT_AUDIENCE_<SUBJECT_DN_HASH>` where the hash is
 * the first 16 hex chars of `SHA-256(subjectDn.lowercase())`. Test/dev adapters
 * compose a static `Map<String, Set<String>>`.
 */
interface JwtAudienceAllowList {
    /**
     * `true` when [subjectDn] is allowed to mint tokens with `aud=[audience]`. A
     * subject DN not present in the allow-list returns `false` for every audience
     * (deny-by-default). An unknown audience for a known subject also returns `false`.
     */
    fun isAllowed(
        subjectDn: String,
        audience: String,
    ): Boolean
}
